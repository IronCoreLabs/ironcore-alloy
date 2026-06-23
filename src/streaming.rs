//! Streaming standard / standard-attached encryption and decryption.
//!
//! This module provides truly streaming AES-256-GCM for large payloads, where neither side needs
//! to hold the whole document in memory. The output is **byte-identical to the one-shot V5 format**
//! (`[0][IRON][IV][ciphertext+tag]`), so a streamed document is just a normal V5 document:
//! encrypt-streaming -> decrypt-one-shot and encrypt-one-shot -> decrypt-streaming both work.
//!
//! # How it works
//!
//! `aes-gcm` (RustCrypto), used elsewhere in alloy/ironcore-documents, only exposes a one-shot
//! `aead::Aead` API that requires the entire plaintext up front. To stream, we decompose GCM into
//! its two incremental parts (the same approach IronOxide/DCP uses):
//!
//! > AES-GCM = AES-CTR (encryption) + GHASH (authentication)
//!
//! - **Encrypt**: run AES-CTR over each plaintext chunk to produce ciphertext, feed that ciphertext
//!   into a running GHASH, and at finalize XOR the GHASH output with `E(J0)` to produce the 16-byte
//!   tag. The wire output is `IV || ciphertext || tag`.
//! - **Decrypt**: the reverse, always holding back the trailing 16 bytes (`held_back`) since they
//!   may be the tag. Everything before `held_back` is run through CTR (producing plaintext) and
//!   GHASH. At finalize the final 16 bytes are the tag, verified with a constant-time comparison.
//!
//! Because this hand-assembles GCM internals (J0 derivation, the data counter starting at 2, the
//! trailing length block) it is proven byte-compatible with the one-shot path by test.
//!
//! # ⚠️ Security: decrypt releases UNVERIFIED plaintext
//!
//! True streaming decrypt is fundamentally incompatible with "verify before releasing any
//! plaintext", because the authentication tag is at the very end of the stream. Therefore
//! [`StreamingStandardDecryptor`]/[`StreamingStandardAttachedDecryptor`] **release plaintext chunks
//! before the tag is verified**, and verification happens only at `finish()`.
//!
//! Callers **may** process decrypted chunks as they arrive (that is the benefit of streaming), but
//! **must** be able to undo whatever they did with them if `finish()` returns `Err`. A failure
//! from `finish()` means every chunk already produced was unauthenticated and may have been
//! attacker-controlled, so any side effect derived from them — a file written, rows inserted, bytes
//! forwarded downstream — must be rolled back, deleted, or otherwise invalidated. The canonical
//! safe pattern is to write decrypted chunks to a temporary file and only commit/rename it after
//! `finish()` succeeds.

use crate::AlloyMetadata;
use crate::errors::AlloyError;
use crate::standard::EdekWithKeyIdHeader;
use crate::util::{take_lock, v4_proto_from_bytes};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use bytes::{Buf, Bytes};
use ctr::Ctr32BE;
use futures::lock::Mutex as AsyncMutex;
use ghash::universal_hash::UniversalHash;
use ghash::{Block, GHash};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::icl_header_v3::V3DocumentHeader;
use ironcore_documents::icl_header_v4::V4DocumentHeader;
use ironcore_documents::v3;
use ironcore_documents::v5::VERSION_AND_MAGIC;
use ironcore_documents::v5::key_id_header::{self, KeyIdHeader};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

/// AES-GCM IV length in bytes.
pub(crate) const IV_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
pub(crate) const TAG_LEN: usize = 16;
/// AES block size in bytes.
const BLOCK_SIZE: usize = 16;
/// Length of the V5 detached header (`0IRON`) that prefixes a non-attached edoc.
const DETACHED_HEADER_LEN: usize = VERSION_AND_MAGIC.len();
/// Length of the key id header that prefixes a V5 attached document.
const KEY_ID_HEADER_LEN: usize = 6;

/// Default streaming chunk / IO block size (64 KiB), matching the DCP default.
///
/// This is the recommended chunk size for caller read loops; it is **not** a constructor parameter
/// in this release. It is exposed as a single named constant (rather than hardcoded into framing or
/// buffer math anywhere downstream) so that making it a tunable constructor argument later is a
/// purely additive change with no format or logic impact.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

type Ctr = Ctr32BE<Aes256>;

/// Build a 128-bit counter block: `IV (96 bits) || counter (32-bit big-endian)`.
fn build_counter_block(iv: &[u8; IV_LEN], counter: u32) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block[..IV_LEN].copy_from_slice(iv);
    block[IV_LEN..].copy_from_slice(&counter.to_be_bytes());
    block
}

/// Derive the GHASH subkey `H = AES_K(0^128)` and the encrypted initial counter block
/// `AES_K(J0)` where `J0 = IV || 0^31 || 1` (used to mask the final tag).
fn init_gcm_state(key: &[u8; 32], iv: &[u8; IV_LEN]) -> (GHash, [u8; TAG_LEN]) {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    // H = AES_K(0^128)
    let mut h = Block::default();
    cipher.encrypt_block(&mut h);
    let ghash = GHash::new(&h);
    // encrypted J0 = AES_K(IV || 0^31 || 1)
    let mut j0 = Block::clone_from_slice(&build_counter_block(iv, 1));
    cipher.encrypt_block(&mut j0);
    let mut encrypted_j0 = [0u8; TAG_LEN];
    encrypted_j0.copy_from_slice(&j0);
    (ghash, encrypted_j0)
}

/// Build a CTR cipher whose counter starts at `J0 + 1 = IV || 0^31 || 2`, matching GCM.
fn ctr_cipher(key: &[u8; 32], iv: &[u8; IV_LEN]) -> Ctr {
    let ctr_block = build_counter_block(iv, 2);
    Ctr::new(
        GenericArray::from_slice(key),
        GenericArray::from_slice(&ctr_block),
    )
}

/// Finalize the GCM tag: append the standard length block `[len(AAD) || len(ciphertext)]` in bits
/// (AAD is always empty for us), then XOR the GHASH output with `AES_K(J0)`.
fn finalize_gcm_tag(
    ghash_acc: GhashAccumulator,
    encrypted_j0: &[u8; TAG_LEN],
    ciphertext_len: u64,
) -> [u8; TAG_LEN] {
    let mut ghash = ghash_acc.finalize();
    let mut len_block = Block::default();
    // First 8 bytes: AAD bit-length (0). Last 8 bytes: ciphertext bit-length.
    len_block[8..].copy_from_slice(&(ciphertext_len * 8).to_be_bytes());
    ghash.update(&[len_block]);
    let ghash_output = ghash.finalize();
    let mut tag = [0u8; TAG_LEN];
    for i in 0..TAG_LEN {
        tag[i] = ghash_output[i] ^ encrypted_j0[i];
    }
    tag
}

/// Accumulates data for GHASH while only feeding it complete 16-byte blocks. Streaming chunks arrive
/// at arbitrary boundaries; this buffers the partial trailing block so GHASH never pads prematurely.
/// Padding of the final partial block happens only at [`GhashAccumulator::finalize`].
struct GhashAccumulator {
    ghash: GHash,
    /// Partial block pending processing (0-15 bytes).
    pending: Vec<u8>,
}

impl GhashAccumulator {
    fn new(ghash: GHash) -> Self {
        Self {
            ghash,
            pending: Vec::with_capacity(BLOCK_SIZE),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        let complete_len = (self.pending.len() / BLOCK_SIZE) * BLOCK_SIZE;
        for chunk in self.pending[..complete_len].chunks_exact(BLOCK_SIZE) {
            self.ghash.update(&[Block::clone_from_slice(chunk)]);
        }
        self.pending.drain(..complete_len);
    }

    fn finalize(mut self) -> GHash {
        if !self.pending.is_empty() {
            let mut block = Block::default();
            block[..self.pending.len()].copy_from_slice(&self.pending);
            self.ghash.update(&[block]);
        }
        self.ghash
    }
}

/// Low-level streaming AES-256-GCM encryptor. Produces output identical to one-shot AES-256-GCM:
/// the concatenation of all `encrypt_chunk` outputs followed by `finalize` is `ciphertext || tag`.
pub(crate) struct GcmStreamEncryptor {
    ctr: Ctr,
    ghash_acc: GhashAccumulator,
    encrypted_j0: [u8; TAG_LEN],
    ciphertext_len: u64,
}

impl GcmStreamEncryptor {
    pub(crate) fn new(key: &[u8; 32], iv: [u8; IV_LEN]) -> Self {
        let (ghash, encrypted_j0) = init_gcm_state(key, &iv);
        Self {
            ctr: ctr_cipher(key, &iv),
            ghash_acc: GhashAccumulator::new(ghash),
            encrypted_j0,
            ciphertext_len: 0,
        }
    }

    /// Encrypt one plaintext chunk in place, returning the ciphertext. CTR is an online cipher, so
    /// output length always equals input length and no bytes are buffered internally.
    pub(crate) fn encrypt_chunk(&mut self, mut chunk: Vec<u8>) -> Vec<u8> {
        self.ctr.apply_keystream(&mut chunk);
        self.ghash_acc.update(&chunk);
        self.ciphertext_len += chunk.len() as u64;
        chunk
    }

    /// Consume the encryptor and produce the 16-byte authentication tag.
    pub(crate) fn finalize(self) -> [u8; TAG_LEN] {
        finalize_gcm_tag(self.ghash_acc, &self.encrypted_j0, self.ciphertext_len)
    }
}

/// Low-level streaming AES-256-GCM decryptor. Releases UNVERIFIED plaintext as it goes; the tag is
/// only verified by [`GcmStreamDecryptor::finalize`]. See the module docs for the caller contract.
pub(crate) struct GcmStreamDecryptor {
    ctr: Ctr,
    ghash_acc: GhashAccumulator,
    encrypted_j0: [u8; TAG_LEN],
    ciphertext_len: u64,
    /// Trailing bytes that might be the GCM tag. We always hold back the last 16 bytes until
    /// `finalize` is called.
    held_back: Vec<u8>,
}

impl GcmStreamDecryptor {
    pub(crate) fn new(key: &[u8; 32], iv: [u8; IV_LEN]) -> Self {
        let (ghash, encrypted_j0) = init_gcm_state(key, &iv);
        Self {
            ctr: ctr_cipher(key, &iv),
            ghash_acc: GhashAccumulator::new(ghash),
            encrypted_j0,
            ciphertext_len: 0,
            held_back: Vec::with_capacity(TAG_LEN),
        }
    }

    /// Decrypt the next ciphertext chunk, returning UNVERIFIED plaintext. The trailing 16 bytes seen
    /// so far are always held back (they may be the tag), so a chunk can produce fewer plaintext
    /// bytes than it contained ciphertext bytes.
    pub(crate) fn decrypt_chunk(&mut self, input: &[u8]) -> Vec<u8> {
        let mut combined = std::mem::take(&mut self.held_back);
        combined.extend_from_slice(input);
        if combined.len() <= TAG_LEN {
            self.held_back = combined;
            return Vec::new();
        }
        let to_process_len = combined.len() - TAG_LEN;
        let mut ciphertext = combined;
        self.held_back = ciphertext.split_off(to_process_len);
        // GHASH is computed over the ciphertext, so update before decrypting in place.
        self.ghash_acc.update(&ciphertext);
        self.ciphertext_len += ciphertext.len() as u64;
        self.ctr.apply_keystream(&mut ciphertext);
        ciphertext
    }

    /// Verify the authentication tag (constant time). On success returns any remaining plaintext
    /// (always empty for CTR, kept for API symmetry). On failure the previously released plaintext
    /// was never authenticated and must not be trusted.
    pub(crate) fn finalize(self) -> Result<Vec<u8>, AlloyError> {
        if self.held_back.len() != TAG_LEN {
            return Err(AlloyError::DecryptError {
                msg: "Ciphertext stream ended before a full authentication tag was received."
                    .to_string(),
            });
        }
        let expected: [u8; TAG_LEN] = self
            .held_back
            .try_into()
            .expect("held_back length checked above");
        let computed = finalize_gcm_tag(self.ghash_acc, &self.encrypted_j0, self.ciphertext_len);
        if bool::from(computed[..].ct_eq(&expected[..])) {
            Ok(Vec::new())
        } else {
            Err(AlloyError::DecryptError {
                msg: "Authentication tag verification failed. Any plaintext already released from \
                      this decryptor was never authenticated and must not be trusted; roll back any \
                      side effects derived from it."
                    .to_string(),
            })
        }
    }
}

fn finalized_error() -> AlloyError {
    AlloyError::InvalidInput {
        msg: "This streaming operation has already been finalized.".to_string(),
    }
}

/// Shared encryptor state used by both the attached and non-attached streaming encryptors. The only
/// difference between the two forms is the bytes staged in `header`.
struct StreamEncryptState {
    /// `None` once `finalize` has been called.
    gcm: Option<GcmStreamEncryptor>,
    /// Stream prefix emitted exactly once, with the first output. For non-attached this is
    /// `0IRON || IV`; for attached it is `key_id_header || edek_len || edek || IV`.
    header: Option<Vec<u8>>,
}

impl StreamEncryptState {
    fn encrypt_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>, AlloyError> {
        let gcm = self.gcm.as_mut().ok_or_else(finalized_error)?;
        let ciphertext = gcm.encrypt_chunk(chunk);
        Ok(match self.header.take() {
            Some(mut header) => {
                header.extend_from_slice(&ciphertext);
                header
            }
            None => ciphertext,
        })
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlloyError> {
        let gcm = self.gcm.take().ok_or_else(finalized_error)?;
        let tag = gcm.finalize();
        // If no chunk was ever encrypted (empty payload) the header still needs to be emitted.
        let mut out = self.header.take().unwrap_or_default();
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

/// Shared decryptor state used by both the attached and non-attached streaming decryptors.
enum StreamDecryptState {
    /// Non-attached only: the DEK is known but the document header (and IV) have not fully arrived.
    /// Buffers leading bytes until the V5 (`0IRON`) or legacy V3 (`3IRON`) header and IV are
    /// available.
    AwaitingHeader { dek: EncryptionKey, buffer: Vec<u8> },
    /// The GCM decryptor is initialized. `pending` holds plaintext produced during construction
    /// (attached leftover ciphertext) that has not yet been returned to the caller. The decryptor is
    /// boxed to keep this enum small (it dwarfs the other variants).
    Streaming {
        gcm: Box<GcmStreamDecryptor>,
        pending: Vec<u8>,
    },
    /// Terminal state: finalized, or an unrecoverable error occurred.
    Done,
}

impl StreamDecryptState {
    fn decrypt_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, AlloyError> {
        match std::mem::replace(self, StreamDecryptState::Done) {
            StreamDecryptState::AwaitingHeader { dek, mut buffer } => {
                buffer.extend_from_slice(input);
                match try_start_non_attached_decrypt(&dek, &buffer)? {
                    None => {
                        // Not enough bytes to parse the header and IV yet; keep buffering.
                        *self = StreamDecryptState::AwaitingHeader { dek, buffer };
                        Ok(Vec::new())
                    }
                    Some((mut gcm, leftover_ciphertext)) => {
                        let plaintext = gcm.decrypt_chunk(&leftover_ciphertext);
                        *self = StreamDecryptState::Streaming {
                            gcm: Box::new(gcm),
                            pending: Vec::new(),
                        };
                        Ok(plaintext)
                    }
                }
            }
            StreamDecryptState::Streaming { mut gcm, pending } => {
                let plaintext = gcm.decrypt_chunk(input);
                *self = StreamDecryptState::Streaming {
                    gcm,
                    pending: Vec::new(),
                };
                Ok(prepend(pending, plaintext))
            }
            StreamDecryptState::Done => Err(finalized_error()),
        }
    }

    fn finalize(&mut self) -> Result<Vec<u8>, AlloyError> {
        match std::mem::replace(self, StreamDecryptState::Done) {
            StreamDecryptState::AwaitingHeader { .. } => Err(AlloyError::DecryptError {
                msg: "Ciphertext stream ended before the document header and IV were received."
                    .to_string(),
            }),
            StreamDecryptState::Streaming { gcm, pending } => {
                let remaining = gcm.finalize()?;
                Ok(prepend(pending, remaining))
            }
            StreamDecryptState::Done => Err(finalized_error()),
        }
    }
}

/// Try to parse a non-attached document header off the front of the buffered stream and initialize
/// the GCM body decryptor. Returns `None` if not enough bytes have arrived yet, or
/// `Some((decryptor, leftover_ciphertext))` once the header and IV are present. Handles both the V5
/// (`0IRON || IV`) and legacy V3 (`3IRON || header_len || V3DocumentHeader || IV`) formats; for V3
/// the header signature (over the tenant header, independent of the body) is verified up front.
/// Errors on an unrecognized header or a failed V3 signature check.
fn try_start_non_attached_decrypt(
    dek: &EncryptionKey,
    buffer: &[u8],
) -> Result<Option<(GcmStreamDecryptor, Vec<u8>)>, AlloyError> {
    if buffer.len() < DETACHED_HEADER_LEN {
        return Ok(None);
    }
    let magic = &buffer[..DETACHED_HEADER_LEN];
    let (iv_start, header_to_verify) = if magic == VERSION_AND_MAGIC {
        // V5: `0IRON || IV`, no signed header.
        (DETACHED_HEADER_LEN, None)
    } else if magic == v3::VERSION_AND_MAGIC {
        // V3: `3IRON || header_len(u16 BE) || V3DocumentHeader || IV`.
        const MAGIC_AND_LEN: usize = DETACHED_HEADER_LEN + 2;
        if buffer.len() < MAGIC_AND_LEN {
            return Ok(None);
        }
        let header_len =
            u16::from_be_bytes([buffer[DETACHED_HEADER_LEN], buffer[DETACHED_HEADER_LEN + 1]])
                as usize;
        let header_end = MAGIC_AND_LEN + header_len;
        if buffer.len() < header_end {
            return Ok(None);
        }
        (header_end, Some(&buffer[MAGIC_AND_LEN..header_end]))
    } else {
        return Err(AlloyError::DecryptError {
            msg: "Streamed document did not start with a recognized `0IRON` (V5) or `3IRON` (V3) \
                  header."
                .to_string(),
        });
    };
    // The IV follows the header; wait until it's fully present.
    if buffer.len() < iv_start + IV_LEN {
        return Ok(None);
    }
    // For V3, verify the header signature (over the tenant header, not the body) before releasing
    // any plaintext — matching the one-shot V3 decrypt path.
    if let Some(header_bytes) = header_to_verify {
        let header: V3DocumentHeader = protobuf::Message::parse_from_bytes(header_bytes)?;
        if !v3::verify_signature(dek.0, &header) {
            return Err(AlloyError::DecryptError {
                msg: "V3 document header signature verification failed.".to_string(),
            });
        }
    }
    let iv: [u8; IV_LEN] = buffer[iv_start..iv_start + IV_LEN]
        .try_into()
        .expect("slice length checked above");
    let gcm = GcmStreamDecryptor::new(&dek.0, iv);
    Ok(Some((gcm, buffer[iv_start + IV_LEN..].to_vec())))
}

/// Returns `front` with `back` appended, avoiding a copy when `front` is empty.
fn prepend(mut front: Vec<u8>, mut back: Vec<u8>) -> Vec<u8> {
    if front.is_empty() {
        back
    } else {
        front.append(&mut back);
        front
    }
}

/// Build the V5 attached document prefix (`key_id_header || edek_len || edek`) from an EDEK that is
/// itself `key_id_header || V4DocumentHeader`.
fn attached_prefix_from_edek(edek: &EdekWithKeyIdHeader) -> Result<Vec<u8>, AlloyError> {
    let bytes = &edek.0.0;
    if bytes.len() < KEY_ID_HEADER_LEN {
        return Err(AlloyError::EncryptError {
            msg: "Generated EDEK was too short to contain a key id header.".to_string(),
        });
    }
    let (header, edek_proto) = bytes.split_at(KEY_ID_HEADER_LEN);
    if edek_proto.len() > u16::MAX as usize {
        return Err(AlloyError::EncryptError {
            msg: "EDEK is too large to be written as an attached document.".to_string(),
        });
    }
    let mut out = Vec::with_capacity(KEY_ID_HEADER_LEN + 2 + edek_proto.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&(edek_proto.len() as u16).to_be_bytes());
    out.extend_from_slice(edek_proto);
    Ok(out)
}

/// Parse the leading bytes of a V5 attached document into its key id header, EDEK, and the start of
/// the edoc (`IV || ciphertext...`). Errors asking for more bytes if `header_bytes` is too short to
/// contain the whole prefix.
fn parse_attached_prefix(
    header_bytes: Vec<u8>,
) -> Result<(KeyIdHeader, V4DocumentHeader, Bytes), AlloyError> {
    let need_more = || AlloyError::InvalidInput {
        msg: "Not enough leading bytes to parse the attached document header. Provide more of the \
              start of the stream (your whole first chunk) when constructing the decryptor."
            .to_string(),
    };
    let (key_id_header, mut rest) =
        key_id_header::decode_version_prefixed_value(Bytes::from(header_bytes))?;
    if rest.len() < 2 {
        return Err(need_more());
    }
    let edek_len = rest.get_u16() as usize;
    if rest.len() < edek_len {
        return Err(need_more());
    }
    let edek_proto = rest.split_to(edek_len);
    let edek = v4_proto_from_bytes(&edek_proto)?;
    Ok((key_id_header, edek, rest))
}

/// A streaming standard (non-attached) encryptor. Construct one via
/// `StandardDocumentOps.create_streaming_encryptor`, then drive it with repeated `encrypt_chunk`
/// calls followed by a single `finish`. The concatenated output is a standard V5 edoc
/// (`0IRON || IV || ciphertext || tag`); the matching EDEK is available from `edek`.
#[derive(uniffi::Object)]
pub struct StreamingStandardEncryptor {
    state: Mutex<StreamEncryptState>,
    edek: EdekWithKeyIdHeader,
}

impl StreamingStandardEncryptor {
    /// Standard V5 framing: the stream is prefixed with `0IRON || IV`.
    pub(crate) fn new(
        dek: EncryptionKey,
        edek: EdekWithKeyIdHeader,
        iv: [u8; IV_LEN],
    ) -> Arc<Self> {
        Self::new_with_header_prefix(dek, edek, iv, VERSION_AND_MAGIC.to_vec())
    }

    /// Like `new`, but `header_prefix` is emitted before the IV instead of the V5 `0IRON` magic.
    /// Used for the legacy V3 (TSC) format, whose prefix is `3IRON || header_len || V3DocumentHeader`.
    /// The IV is appended here so it always matches the IV driving the GCM stream.
    pub(crate) fn new_with_header_prefix(
        dek: EncryptionKey,
        edek: EdekWithKeyIdHeader,
        iv: [u8; IV_LEN],
        header_prefix: Vec<u8>,
    ) -> Arc<Self> {
        let mut header = header_prefix;
        header.extend_from_slice(&iv);
        Arc::new(Self {
            state: Mutex::new(StreamEncryptState {
                gcm: Some(GcmStreamEncryptor::new(&dek.0, iv)),
                header: Some(header),
            }),
            edek,
        })
    }
}

#[uniffi::export]
impl StreamingStandardEncryptor {
    /// The EDEK (encrypted document encryption key) for this stream. Store it alongside the
    /// streamed edoc; it is required to decrypt. Available immediately after construction.
    pub fn edek(&self) -> EdekWithKeyIdHeader {
        self.edek.clone()
    }

    /// Encrypt the next chunk of plaintext, returning the corresponding ciphertext. The very first
    /// returned chunk is prefixed with the `0IRON` header and IV.
    pub fn encrypt_chunk(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).encrypt_chunk(plaintext)
    }

    /// Finish the stream, returning the final ciphertext bytes and the authentication tag. Must be
    /// called exactly once, after all `encrypt_chunk` calls.
    pub fn finish(&self) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).finalize()
    }
}

/// A streaming standard (non-attached) decryptor.
///
/// Construct one via `StandardDocumentOps.create_streaming_decryptor` (passing the EDEK), then feed
/// the streamed edoc with repeated `decrypt_chunk` calls and call `finish` once at the end.
///
/// # ⚠️ `decrypt_chunk` returns UNVERIFIED plaintext
///
/// The authentication tag is at the end of the stream, so plaintext is released before it is
/// verified. You **may** use chunks as they arrive, but you **must** be able to undo everything you
/// did with them if `finish` returns `Err` — a failure means the released plaintext was never
/// authenticated and may have been attacker-controlled. Prefer writing to a temp file and only
/// committing it after `finish` succeeds. See the module documentation for details.
#[derive(uniffi::Object)]
pub struct StreamingStandardDecryptor {
    state: Mutex<StreamDecryptState>,
}

impl StreamingStandardDecryptor {
    pub(crate) fn new(dek: EncryptionKey) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StreamDecryptState::AwaitingHeader {
                dek,
                buffer: Vec::new(),
            }),
        })
    }
}

#[uniffi::export]
impl StreamingStandardDecryptor {
    /// Decrypt the next chunk of ciphertext, returning UNVERIFIED plaintext (see the type docs).
    /// Early chunks may return empty while the IV and held-back tag bytes are buffered.
    pub fn decrypt_chunk(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).decrypt_chunk(&ciphertext)
    }

    /// Verify the authentication tag and return any remaining plaintext. An `Err` means the
    /// plaintext already released from `decrypt_chunk` was never authenticated and must not be
    /// trusted; roll back any side effects derived from it.
    pub fn finish(&self) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).finalize()
    }
}

/// A streaming standard-attached encryptor. Like [`StreamingStandardEncryptor`] but the EDEK is
/// written inline at the front of the stream, so there is no separate `edek` to store. The output
/// is a standard V5 attached document.
#[derive(uniffi::Object)]
pub struct StreamingStandardAttachedEncryptor {
    state: Mutex<StreamEncryptState>,
}

impl StreamingStandardAttachedEncryptor {
    pub(crate) fn new(
        dek: EncryptionKey,
        edek: EdekWithKeyIdHeader,
        iv: [u8; IV_LEN],
    ) -> Result<Arc<Self>, AlloyError> {
        // Attached framing: key_id_header || edek_len || edek || IV || ciphertext || tag. Note the
        // edoc has no `0IRON` prefix, matching the one-shot attached format.
        let mut header = attached_prefix_from_edek(&edek)?;
        header.extend_from_slice(&iv);
        Ok(Arc::new(Self {
            state: Mutex::new(StreamEncryptState {
                gcm: Some(GcmStreamEncryptor::new(&dek.0, iv)),
                header: Some(header),
            }),
        }))
    }
}

#[uniffi::export]
impl StreamingStandardAttachedEncryptor {
    /// Encrypt the next chunk of plaintext. The very first returned chunk is prefixed with the
    /// attached document header (key id header + EDEK) and the IV.
    pub fn encrypt_chunk(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).encrypt_chunk(plaintext)
    }

    /// Finish the stream, returning the final ciphertext bytes and the authentication tag.
    pub fn finish(&self) -> Result<Vec<u8>, AlloyError> {
        take_lock(&self.state).finalize()
    }
}

/// Asynchronously unwraps a streamed attached document's inline EDEK to its DEK. Implemented by the
/// per-backend standard clients (Standalone derives locally; SaaS Shield calls the TSP). This lets
/// the generic attached decryptor stay backend-agnostic while still performing the (possibly async)
/// unwrap once it has parsed the inline EDEK off the front of the stream.
#[async_trait::async_trait]
pub(crate) trait StreamingDekUnwrapper: Send + Sync {
    async fn unwrap_streaming_dek(
        &self,
        edek: EdekWithKeyIdHeader,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptionKey, AlloyError>;
}

/// Decryptor state for the attached stream, whose EDEK and IV are discovered inline.
enum AttachedDecryptState {
    /// Buffering the start of the stream until the inline EDEK + IV can be parsed.
    AwaitingHeader { buffer: Vec<u8> },
    /// GCM initialized; `pending` holds plaintext produced from leftover header bytes.
    Streaming {
        gcm: Box<GcmStreamDecryptor>,
        pending: Vec<u8>,
    },
    /// Terminal state: finalized, or an unrecoverable error occurred.
    Done,
}

/// A streaming standard-attached decryptor.
///
/// Feed the attached document to `decrypt_chunk` exactly as it comes off the wire — the leading
/// EDEK and IV are parsed off the front of the stream for you, so you never need to know or split
/// the header format. Early chunks may return empty while that header is buffered. Because the
/// inline EDEK must be unwrapped before any ciphertext can be decrypted (a TSP call under SaaS
/// Shield), `decrypt_chunk` and `finish` are async. Only the V5 attached format is supported.
///
/// # ⚠️ `decrypt_chunk` returns UNVERIFIED plaintext
///
/// The same release-of-unverified-plaintext contract as [`StreamingStandardDecryptor`] applies: be
/// prepared to roll back if `finish` returns `Err`. See the module documentation.
#[derive(uniffi::Object)]
pub struct StreamingStandardAttachedDecryptor {
    unwrapper: Arc<dyn StreamingDekUnwrapper>,
    metadata: AlloyMetadata,
    // Async mutex because the lock is held across the `.await` that unwraps the inline EDEK.
    state: AsyncMutex<AttachedDecryptState>,
}

impl StreamingStandardAttachedDecryptor {
    pub(crate) fn new(
        unwrapper: Arc<dyn StreamingDekUnwrapper>,
        metadata: AlloyMetadata,
    ) -> Arc<Self> {
        Arc::new(Self {
            unwrapper,
            metadata,
            state: AsyncMutex::new(AttachedDecryptState::AwaitingHeader { buffer: Vec::new() }),
        })
    }
}

#[uniffi::export]
impl StreamingStandardAttachedDecryptor {
    /// Decrypt the next chunk of the attached document, returning UNVERIFIED plaintext (see the type
    /// docs). Feed the stream from its very start; early chunks may return empty while the inline
    /// EDEK and IV are buffered and the DEK is unwrapped.
    pub async fn decrypt_chunk(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, AlloyError> {
        let mut guard = self.state.lock().await;
        match std::mem::replace(&mut *guard, AttachedDecryptState::Done) {
            AttachedDecryptState::AwaitingHeader { mut buffer } => {
                buffer.extend_from_slice(&ciphertext);
                match try_parse_attached_start(&buffer)? {
                    None => {
                        // Not enough bytes to parse the inline EDEK + IV yet; keep buffering.
                        *guard = AttachedDecryptState::AwaitingHeader { buffer };
                        Ok(Vec::new())
                    }
                    Some((edek, iv, leftover)) => {
                        let dek = self
                            .unwrapper
                            .unwrap_streaming_dek(edek, &self.metadata)
                            .await?;
                        let mut gcm = GcmStreamDecryptor::new(&dek.0, iv);
                        let plaintext = gcm.decrypt_chunk(&leftover);
                        *guard = AttachedDecryptState::Streaming {
                            gcm: Box::new(gcm),
                            pending: Vec::new(),
                        };
                        Ok(plaintext)
                    }
                }
            }
            AttachedDecryptState::Streaming { mut gcm, pending } => {
                let plaintext = gcm.decrypt_chunk(&ciphertext);
                *guard = AttachedDecryptState::Streaming {
                    gcm,
                    pending: Vec::new(),
                };
                Ok(prepend(pending, plaintext))
            }
            AttachedDecryptState::Done => Err(finalized_error()),
        }
    }

    /// Verify the authentication tag and return any remaining plaintext. An `Err` means the released
    /// plaintext was never authenticated and must not be trusted.
    pub async fn finish(&self) -> Result<Vec<u8>, AlloyError> {
        let mut guard = self.state.lock().await;
        match std::mem::replace(&mut *guard, AttachedDecryptState::Done) {
            AttachedDecryptState::AwaitingHeader { .. } => Err(AlloyError::DecryptError {
                msg: "Ciphertext stream ended before the attached document header was received."
                    .to_string(),
            }),
            AttachedDecryptState::Streaming { gcm, pending } => {
                let remaining = gcm.finalize()?;
                Ok(prepend(pending, remaining))
            }
            AttachedDecryptState::Done => Err(finalized_error()),
        }
    }
}

/// The reconstructed EDEK, IV, and leftover ciphertext parsed from the start of an attached stream.
type ParsedAttachedStart = (EdekWithKeyIdHeader, [u8; IV_LEN], Vec<u8>);

/// Try to parse the inline EDEK + IV off the front of a buffered attached stream. Returns `None` if
/// not enough bytes have arrived yet, or `Some((edek, iv, leftover_ciphertext))` once the full
/// header and IV are present. Errors only on a genuinely malformed header.
fn try_parse_attached_start(buffer: &[u8]) -> Result<Option<ParsedAttachedStart>, AlloyError> {
    // key_id_header (6) + the u16 EDEK length must be present to know how long the header is.
    if buffer.len() < KEY_ID_HEADER_LEN + 2 {
        return Ok(None);
    }
    let edek_len =
        u16::from_be_bytes([buffer[KEY_ID_HEADER_LEN], buffer[KEY_ID_HEADER_LEN + 1]]) as usize;
    // Full prefix = key_id_header + length + EDEK + IV.
    if buffer.len() < KEY_ID_HEADER_LEN + 2 + edek_len + IV_LEN {
        return Ok(None);
    }
    let (key_id_header, edek, mut edoc) = parse_attached_prefix(buffer.to_vec())?;
    let iv: [u8; IV_LEN] = edoc
        .split_to(IV_LEN)
        .as_ref()
        .try_into()
        .expect("length checked above");
    Ok(Some((
        EdekWithKeyIdHeader::new(key_id_header, edek),
        iv,
        edoc.to_vec(),
    )))
}

#[cfg(test)]
mod test {
    use super::*;
    use aes_gcm::{Aes256Gcm, KeyInit as GcmKeyInit, aead::Aead};
    use proptest::prelude::*;

    const KEY: [u8; 32] = [7u8; 32];
    const IV: [u8; IV_LEN] = [9u8; IV_LEN];

    /// One-shot AES-256-GCM via the same `aes-gcm` crate alloy/ironcore-documents use, producing
    /// `ciphertext || tag` — the load-bearing reference for byte-compatibility.
    fn one_shot(key: &[u8; 32], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        cipher
            .encrypt(GenericArray::from_slice(iv), plaintext)
            .unwrap()
    }

    fn stream_encrypt_all(key: &[u8; 32], iv: [u8; IV_LEN], chunks: &[&[u8]]) -> Vec<u8> {
        let mut enc = GcmStreamEncryptor::new(key, iv);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend_from_slice(&enc.encrypt_chunk(chunk.to_vec()));
        }
        out.extend_from_slice(&enc.finalize());
        out
    }

    #[test]
    fn stream_encrypt_matches_one_shot() {
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let expected = one_shot(&KEY, &IV, &plaintext);
        let streamed = stream_encrypt_all(&KEY, IV, &[&plaintext]);
        assert_eq!(streamed, expected);
    }

    #[test]
    fn stream_encrypt_empty_matches_one_shot() {
        let expected = one_shot(&KEY, &IV, &[]);
        let streamed = stream_encrypt_all(&KEY, IV, &[]);
        assert_eq!(streamed, expected);
        // Empty plaintext is just the tag.
        assert_eq!(streamed.len(), TAG_LEN);
    }

    #[test]
    fn stream_encrypt_chunk_boundaries_are_irrelevant() {
        // 100 bytes split many ways must all equal the one-shot output.
        let plaintext: Vec<u8> = (0..100u8).collect();
        let expected = one_shot(&KEY, &IV, &plaintext);
        // single giant chunk
        assert_eq!(stream_encrypt_all(&KEY, IV, &[&plaintext]), expected);
        // 1-byte chunks
        let singles: Vec<&[u8]> = plaintext.iter().map(std::slice::from_ref).collect();
        assert_eq!(stream_encrypt_all(&KEY, IV, &singles), expected);
        // straddling the 16-byte block boundary
        let (a, b) = plaintext.split_at(17);
        let (b, c) = b.split_at(15);
        assert_eq!(stream_encrypt_all(&KEY, IV, &[a, b, c]), expected);
    }

    fn stream_decrypt_all(
        key: &[u8; 32],
        iv: [u8; IV_LEN],
        ct_and_tag: &[u8],
        chunk: usize,
    ) -> Vec<u8> {
        let mut dec = GcmStreamDecryptor::new(key, iv);
        let mut out = Vec::new();
        for piece in ct_and_tag.chunks(chunk.max(1)) {
            out.extend_from_slice(&dec.decrypt_chunk(piece));
        }
        out.extend_from_slice(&dec.finalize().unwrap());
        out
    }

    #[test]
    fn stream_decrypt_matches_one_shot_input() {
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let ct_and_tag = one_shot(&KEY, &IV, &plaintext);
        for chunk in [1usize, 7, 16, 17, 1000] {
            assert_eq!(stream_decrypt_all(&KEY, IV, &ct_and_tag, chunk), plaintext);
        }
    }

    #[test]
    fn stream_roundtrip_empty() {
        let streamed = stream_encrypt_all(&KEY, IV, &[]);
        assert_eq!(stream_decrypt_all(&KEY, IV, &streamed, 3), Vec::<u8>::new());
    }

    #[test]
    fn tampered_byte_fails_verification() {
        let plaintext = b"authenticate me".to_vec();
        let mut ct_and_tag = one_shot(&KEY, &IV, &plaintext);
        ct_and_tag[0] ^= 0xff; // flip a ciphertext byte
        let mut dec = GcmStreamDecryptor::new(&KEY, IV);
        let _ = dec.decrypt_chunk(&ct_and_tag);
        assert!(matches!(
            dec.finalize(),
            Err(AlloyError::DecryptError { .. })
        ));
    }

    #[test]
    fn tampered_tag_fails_verification() {
        let plaintext = b"authenticate me".to_vec();
        let mut ct_and_tag = one_shot(&KEY, &IV, &plaintext);
        let last = ct_and_tag.len() - 1;
        ct_and_tag[last] ^= 0x01; // flip a tag byte
        let mut dec = GcmStreamDecryptor::new(&KEY, IV);
        let _ = dec.decrypt_chunk(&ct_and_tag);
        assert!(matches!(
            dec.finalize(),
            Err(AlloyError::DecryptError { .. })
        ));
    }

    #[test]
    fn truncated_stream_fails_verification() {
        let plaintext = b"authenticate me".to_vec();
        let mut ct_and_tag = one_shot(&KEY, &IV, &plaintext);
        ct_and_tag.truncate(ct_and_tag.len() - 4); // drop part of the tag
        let mut dec = GcmStreamDecryptor::new(&KEY, IV);
        let _ = dec.decrypt_chunk(&ct_and_tag);
        assert!(dec.finalize().is_err());
    }

    proptest! {
        // Streamed output equals one-shot output exactly for random plaintext and chunking.
        #[test]
        fn prop_stream_equals_one_shot(
            plaintext in proptest::collection::vec(any::<u8>(), 0..2000usize),
            chunk_size in 1usize..256,
        ) {
            let expected = one_shot(&KEY, &IV, &plaintext);
            let chunks: Vec<&[u8]> = if plaintext.is_empty() {
                vec![]
            } else {
                plaintext.chunks(chunk_size).collect()
            };
            let streamed = stream_encrypt_all(&KEY, IV, &chunks);
            prop_assert_eq!(&streamed, &expected);
            // And it decrypts back, regardless of decrypt chunking.
            let decrypted = stream_decrypt_all(&KEY, IV, &streamed, chunk_size);
            prop_assert_eq!(decrypted, plaintext);
        }
    }
}
