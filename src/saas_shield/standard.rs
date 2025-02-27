use super::{SaasShieldSecurityEventOps, SecurityEvent};
use crate::errors::AlloyError;
use crate::standard::{
    EdekWithKeyIdHeader, EncryptedDocument, EncryptedDocuments, PlaintextDocument,
    PlaintextDocumentWithEdek, PlaintextDocuments, PlaintextDocumentsWithEdeks,
    RekeyEdeksBatchResult, StandardDecryptBatchResult, StandardDocumentOps,
    StandardEncryptBatchResult, decrypt_document_core, encrypt_document_core, encrypt_map,
    verify_sig,
};
use crate::tenant_security_client::{
    BatchUnwrapKeyResponse, BatchWrapKeyResponse, RequestMetadata, TenantSecurityClient,
    UnwrapKeyResponse, WrapKeyResponse,
};
use crate::util::{BatchResult, OurReseedingRng, perform_batch_action, v4_proto_from_bytes};
use crate::{AlloyMetadata, alloy_client_trait::AlloyClient};
use crate::{DocumentId, FieldId, PlaintextBytes, TenantId};
use bytes::Bytes;
use futures::future::{FutureExt, join_all};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::cmk_edek;
use ironcore_documents::cmk_edek::EncryptedDek;
use ironcore_documents::icl_header_v4::v4document_header::EdekWrapper;
use ironcore_documents::icl_header_v4::{self, V4DocumentHeader};
use ironcore_documents::v4::validate_v4_header;
use ironcore_documents::v5::key_id_header::{
    EdekType, KeyId, KeyIdHeader, PayloadType, decode_version_prefixed_value,
};
use itertools::Itertools;
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;
use std::convert::identity;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct SaasShieldStandardClient {
    tenant_security_client: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

// Standard SaaS Shield edeks could be V3 if they originated in old TSCs or V4 if they originated from Cloaked Search.
#[derive(Debug)]
enum EdekParts {
    /// Key ID and document header containing the EDEK
    V5(KeyId, V4DocumentHeader),
    V4(V4DocumentHeader),
    /// Just the EDEK, ready to be sent to the TSP
    V3(Bytes),
}

impl EdekParts {
    /// Gets the EDEK bytes regardless of the type of EDEK this was. These are the proto-encoded
    /// EncryptedDeks bytes ready to send to the TSP.
    fn get_edek_bytes(&self) -> Result<Vec<u8>, AlloyError> {
        match self {
            EdekParts::V5(kms_config_id, v4_document_header) => {
                let fixed_edek = fix_encrypted_dek(find_cmk_edek_v5(
                    &v4_document_header.signed_payload.edeks,
                    kms_config_id.0,
                )?)?;
                let edek_bytes = fixed_edek
                    .write_to_bytes()
                    .expect("Writing to bytes is safe");
                Ok(edek_bytes)
            }
            EdekParts::V4(v4_document_header) => {
                let fixed_edek =
                    fix_encrypted_dek(find_cmk_edek_v4(&v4_document_header.signed_payload.edeks)?)?;
                let edek_bytes = fixed_edek
                    .write_to_bytes()
                    .expect("Writing to bytes is safe");
                Ok(edek_bytes)
            }
            EdekParts::V3(b) => Ok(b.to_vec()),
        }
    }

    /// Validates the signature in the case of V4 document header. V3 doesn't need validation
    fn validate_signature(&self, enc_key: EncryptionKey) -> Result<(), AlloyError> {
        match self {
            EdekParts::V5(_, document_header) | EdekParts::V4(document_header) => {
                verify_sig(enc_key, document_header)
            }
            EdekParts::V3(_) => Ok(()), // This is just an EDEK, so doesn't require validation
        }
    }
}

impl SaasShieldStandardClient {
    pub(crate) fn new(tenant_security_client: Arc<TenantSecurityClient>) -> Self {
        SaasShieldStandardClient {
            tenant_security_client,
            rng: crate::util::create_reseeding_rng(),
        }
    }

    fn encrypt_document<R: RngCore + CryptoRng + Send>(
        rng: Arc<Mutex<R>>,
        tsc_edek: Vec<u8>,
        dek: EncryptionKey,
        tenant_id: &TenantId,
        document: HashMap<FieldId, PlaintextBytes>,
    ) -> Result<EncryptedDocument, AlloyError> {
        let pb_edeks: ironcore_documents::cmk_edek::EncryptedDeks =
            protobuf::Message::parse_from_bytes(&tsc_edek)?;

        // We will choose the first edek, so that's the id we want to put on the front.
        let kms_config_id = pb_edeks
            .encryptedDeks
            .first()
            .map(|edek| edek.kmsConfigId as u32)
            .unwrap_or(0);
        let v4_doc = generate_cmk_v4_doc_and_sign(pb_edeks.encryptedDeks, dek, tenant_id)?;

        encrypt_document_core(
            document,
            rng,
            dek,
            Self::create_key_id_header(kms_config_id),
            v4_doc,
        )
    }

    async fn rekey_edek_core(
        &self,
        edek: EdekWithKeyIdHeader,
        parsed_new_tenant_id: &TenantId,
        request_metadata: &RequestMetadata,
    ) -> Result<EdekWithKeyIdHeader, AlloyError> {
        let edek_parts = Self::decompose_edek_header(edek)?;
        let edek = edek_parts.get_edek_bytes()?;
        let tsp_resp = self
            .tenant_security_client
            .rekey_edek(edek, parsed_new_tenant_id, request_metadata)
            .await?;
        let dek = tsc_dek_to_encryption_key(tsp_resp.dek.0)?;
        edek_parts.validate_signature(dek)?;
        Self::encrypt_document(
            self.rng.clone(), // this isn't actually used because of the empty document
            tsp_resp.edek.0,
            dek,
            parsed_new_tenant_id,
            HashMap::new(), // empty document. We only care about the EDEK part and there's no wasted work
        )
        .map(|doc| doc.edek)
    }

    /// Break the EDEK into its V3, V4 or V5 parts. This should be used instead of Self::decompose_key_id_header
    /// in order to support V3 and V4 headers.
    fn decompose_edek_header(
        encrypted_bytes: EdekWithKeyIdHeader,
    ) -> Result<EdekParts, AlloyError> {
        // This doesn't just call Self::decompose_key_id_header because we still want to error on incorrect EDEK/payload type
        let maybe_decomposed =
            decode_version_prefixed_value(Bytes::copy_from_slice(&encrypted_bytes.0.0));
        match maybe_decomposed {
            Ok((
                KeyIdHeader {
                    key_id,
                    edek_type,
                    payload_type,
                },
                remaining_bytes,
            )) => {
                // standard_attached uses a key ID of 0 to indicate V4 headers, as they can't exist in V5
                if key_id.0 == 0 {
                    Ok(v4_proto_from_bytes(&remaining_bytes).map(EdekParts::V4)?)
                } else {
                    let expected_edek_type = Self::get_edek_type();
                    let expected_payload_type = Self::get_payload_type();
                    if edek_type == expected_edek_type && payload_type == expected_payload_type {
                        let v4_document_header = v4_proto_from_bytes(remaining_bytes)?;
                        Ok(EdekParts::V5(key_id, v4_document_header))
                    } else {
                        Err(AlloyError::InvalidInput {
                            msg: format!(
                                "The data indicated that this was not a {expected_edek_type} {expected_payload_type} wrapped value. Found: {edek_type}, {payload_type}"
                            ),
                        })
                    }
                }
            }
            // This is the case where the value did not have a key id header. This means it's either a v4 or v3.
            Err(_) => {
                Ok(v4_proto_from_bytes(&encrypted_bytes.0)
                    .ok()
                    .and_then(|maybe_parsed_v4| {
                        // Check that the parsing succeeded, meaning it is actually V4
                        validate_v4_header(&maybe_parsed_v4).then(|| EdekParts::V4(maybe_parsed_v4))
                    })
                    .unwrap_or(
                        // Parsing as V4 failed, so V3 is our fallback
                        EdekParts::V3(encrypted_bytes.0.0.into()),
                    ))
            }
        }
    }

    /// Decompose EDEKs with headers and make a request to the TSP to unwrap them.
    /// Returns the TSP's unwrap response and a map from document IDs to EDEK failures.
    async fn batch_unwrap_edeks<'a, T>(
        &self,
        edeks_with_headers: T,
        metadata: &AlloyMetadata,
    ) -> Result<(BatchUnwrapKeyResponse, HashMap<DocumentId, AlloyError>), AlloyError>
    where
        T: IntoParallelIterator<Item = (&'a str, EdekWithKeyIdHeader)>,
    {
        let request_metadata = metadata.clone().try_into()?;
        let decompose_edek = |edek_with_header: EdekWithKeyIdHeader| {
            let edek_parts = Self::decompose_edek_header(edek_with_header)?;
            edek_parts.get_edek_bytes()
        };
        let BatchResult {
            successes: edeks,
            failures: edek_failures_str,
        } = perform_batch_action(edeks_with_headers, decompose_edek);
        let edek_failures = edek_failures_str
            .into_iter()
            .map(|(k, v)| (DocumentId(k.to_string()), v))
            .collect();
        let batch_unwrap_response = self
            .tenant_security_client
            .batch_unwrap_keys(edeks, &request_metadata)
            .await?;
        Ok((batch_unwrap_response, edek_failures))
    }
}

impl AlloyClient for SaasShieldStandardClient {
    fn get_edek_type() -> EdekType {
        EdekType::SaasShield
    }

    fn get_payload_type() -> PayloadType {
        PayloadType::StandardEdek
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl StandardDocumentOps for SaasShieldStandardClient {
    /// Encrypt a document with the provided metadata. The document must be a map from field identifiers to plaintext
    /// bytes, and the same metadata must be provided when decrypting the document.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key, then each field of the
    /// document will be encrypted separately using a random IV and this single generated DEK.
    /// The result contains a map from field identifiers to encrypted bytes as well as the EDEK (encrypted document
    /// encryption key) used for encryption.
    /// The document is encrypted differently with each call, so the result is not suited for exact matches or indexing.
    /// For the same reason however the strongest protection of the document is provided by this method.
    /// To support these uses, see the `DeterministicFieldOps.encrypt` function.
    async fn encrypt(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let WrapKeyResponse {
            dek,
            edek: tsc_edek,
        } = self
            .tenant_security_client
            .wrap_key(&request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        Self::encrypt_document(
            self.rng.clone(),
            tsc_edek.0,
            enc_key,
            &metadata.tenant_id,
            plaintext_document.0,
        )
    }

    /// Encrypt each of the provided documents with the provided metadata.
    /// Note that because only a single metadata value is passed, each document will be encrypted to the same tenant.
    async fn encrypt_batch(
        &self,
        plaintext_documents: PlaintextDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardEncryptBatchResult, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let document_ids = plaintext_documents.0.keys().map(|d| d.0.as_str()).collect();
        let BatchWrapKeyResponse {
            keys,
            failures: tsp_failures,
        } = self
            .tenant_security_client
            .batch_wrap_keys(document_ids, &request_metadata)
            .await?;
        let docs_and_keys = plaintext_documents
            .0
            .into_par_iter()
            .map(|(document_id, document)| {
                let maybe_keys = keys.get(&document_id.0);
                (document_id, (document, maybe_keys.cloned()))
            });
        let encrypt_document =
            |(plaintext_document, maybe_keys): (PlaintextDocument, Option<WrapKeyResponse>)| {
                let WrapKeyResponse { dek, edek } =
                    maybe_keys.ok_or_else(|| AlloyError::EncryptError {
                        msg: "TSP failed to wrap key for document.".to_string(),
                    })?;
                let enc_key = tsc_dek_to_encryption_key(dek.0)?;
                Self::encrypt_document(
                    self.rng.clone(),
                    edek.0,
                    enc_key,
                    &metadata.tenant_id,
                    plaintext_document.0,
                )
            };
        let encryption_result = perform_batch_action(docs_and_keys, encrypt_document);
        let combined_failures = tsp_failures
            .into_iter()
            .map(|(k, err)| (DocumentId(k), err.into()))
            .chain(encryption_result.failures)
            .collect();
        Ok(BatchResult {
            successes: encryption_result.successes,
            failures: combined_failures,
        }
        .into())
    }

    /// Decrypt a document that was encrypted with the provided metadata. The document must have been encrypted with one
    /// of the `StandardDocumentOps.encrypt` functions. The result contains a map from field identifiers to decrypted
    /// bytes.
    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let edek_parts = Self::decompose_edek_header(encrypted_document.edek)?;
        let edek = edek_parts.get_edek_bytes()?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(edek, &request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        edek_parts.validate_signature(enc_key)?;
        decrypt_document_core(encrypted_document.document, enc_key).map(PlaintextDocument)
    }

    /// Decrypt each of the provided documents with the provided metadata.
    /// Note that because the metadata is shared between the documents, they all must correspond to the
    /// same tenant ID.
    async fn decrypt_batch(
        &self,
        encrypted_documents: EncryptedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardDecryptBatchResult, AlloyError> {
        let edeks_with_headers = encrypted_documents
            .0
            .par_iter()
            .map(|(k, v)| (k.0.as_str(), v.edek.clone()));
        let (batch_unwrap_response, edek_failures) = self
            .batch_unwrap_edeks(edeks_with_headers, metadata)
            .await?;
        let docs_and_keys = encrypted_documents
            .0
            .into_par_iter()
            .map(|(document_id, document)| {
                let maybe_keys = batch_unwrap_response.keys.get(&document_id.0);
                (document_id, (document, maybe_keys.cloned()))
            });
        let decrypt_document =
            |(encrypted_document, maybe_keys): (EncryptedDocument, Option<UnwrapKeyResponse>)| {
                let UnwrapKeyResponse { dek } =
                    maybe_keys.ok_or_else(|| AlloyError::DecryptError {
                        msg: "TSP failed to wrap key for document.".to_string(),
                    })?;
                let edek_parts = Self::decompose_edek_header(encrypted_document.edek)?;
                let enc_key = tsc_dek_to_encryption_key(dek.0)?;
                edek_parts.validate_signature(enc_key)?;
                decrypt_document_core(encrypted_document.document, enc_key).map(PlaintextDocument)
            };
        let decryption_result = perform_batch_action(docs_and_keys, decrypt_document);
        let combined_failures = batch_unwrap_response
            .failures
            .into_iter()
            .map(|(k, err)| (DocumentId(k), err.into()))
            .chain(edek_failures)
            .chain(decryption_result.failures)
            .collect();
        Ok(BatchResult {
            successes: decryption_result.successes,
            failures: combined_failures,
        }
        .into())
    }

    /// Decrypt the provided EDEKs and re-encrypt them using the tenant's current key. If `new_tenant_id` is `None`,
    /// the EDEK will be encrypted to the original tenant. Because the underlying DEK does not change, a document
    /// associated with the old EDEK can be decrypted with the new EDEK without changing its document data.
    async fn rekey_edeks(
        &self,
        edeks: HashMap<DocumentId, EdekWithKeyIdHeader>,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyEdeksBatchResult, AlloyError> {
        let parsed_new_tenant_id = new_tenant_id.as_ref().unwrap_or(&metadata.tenant_id);
        let request_metadata = metadata.clone().try_into()?;
        let tsp_responses = join_all(edeks.into_iter().map(|(id, edek)| {
            self.rekey_edek_core(edek, parsed_new_tenant_id, &request_metadata)
                .map(|res| (id, res))
        }))
        .await;
        Ok(perform_batch_action(tsp_responses, identity).into())
    }

    /// Encrypt a document with the provided metadata. The document must be a map from field identifiers to plaintext
    /// bytes, and the same metadata must be provided when decrypting the document.
    /// The provided EDEK will be decrypted and used to encrypt each field. This is useful when updating some fields
    /// of the document.
    async fn encrypt_with_existing_edek(
        &self,
        plaintext_document: PlaintextDocumentWithEdek,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let edek_parts = Self::decompose_edek_header(plaintext_document.edek.clone())?;
        let edek = edek_parts.get_edek_bytes()?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(edek, &request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        edek_parts.validate_signature(enc_key)?;
        Ok(EncryptedDocument {
            document: encrypt_map(plaintext_document.document.0, self.rng.clone(), enc_key)?,
            edek: plaintext_document.edek,
        })
    }

    /// Encrypt multiple documents with the provided metadata.
    /// The provided EDEKs will be decrypted and used to encrypt each corresponding document's fields.
    /// This is useful when updating some fields of the document.
    async fn encrypt_with_existing_edek_batch(
        &self,
        plaintext_documents: PlaintextDocumentsWithEdeks,
        metadata: &AlloyMetadata,
    ) -> Result<StandardEncryptBatchResult, AlloyError> {
        let edeks_with_headers = plaintext_documents
            .0
            .par_iter()
            .map(|(k, v)| (k.0.as_str(), v.edek.clone()));
        let (batch_unwrap_response, edek_failures) = self
            .batch_unwrap_edeks(edeks_with_headers, metadata)
            .await?;
        let docs_and_keys = plaintext_documents
            .0
            .into_par_iter()
            .map(|(document_id, document)| {
                let maybe_keys = batch_unwrap_response.keys.get(&document_id.0);
                (document_id, (document, maybe_keys.cloned()))
            });
        let encrypt_document = |(plaintext_document, maybe_keys): (
            PlaintextDocumentWithEdek,
            Option<UnwrapKeyResponse>,
        )| {
            let UnwrapKeyResponse { dek } = maybe_keys.ok_or_else(|| AlloyError::DecryptError {
                msg: "TSP failed to wrap key for document.".to_string(),
            })?;
            let edek_parts = Self::decompose_edek_header(plaintext_document.edek)?;
            let enc_key = tsc_dek_to_encryption_key(dek.0)?;
            edek_parts.validate_signature(enc_key)?;
            Self::encrypt_document(
                self.rng.clone(),
                edek_parts.get_edek_bytes()?,
                enc_key,
                &metadata.tenant_id,
                plaintext_document.document.0,
            )
        };
        let decryption_result = perform_batch_action(docs_and_keys, encrypt_document);
        let combined_failures = batch_unwrap_response
            .failures
            .into_iter()
            .map(|(k, err)| (DocumentId(k), err.into()))
            .chain(edek_failures)
            .chain(decryption_result.failures)
            .collect();
        Ok(BatchResult {
            successes: decryption_result.successes,
            failures: combined_failures,
        }
        .into())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SaasShieldSecurityEventOps for SaasShieldStandardClient {
    /// Log the security event `event` to the tenant's log sink.
    /// If the event time is unspecified the current time will be used.
    async fn log_security_event(
        &self,
        event: SecurityEvent,
        metadata: &AlloyMetadata,
        event_time_millis: Option<i64>,
    ) -> Result<(), AlloyError> {
        let request_metadata = (metadata.clone(), event_time_millis).try_into()?;
        self.tenant_security_client
            .log_security_event(&event, &request_metadata)
            .await
    }
}

fn find_cmk_edek_v5(
    edeks: &[EdekWrapper],
    kms_config_id: u32,
) -> Result<&EncryptedDek, AlloyError> {
    let maybe_cmk_edeks = edeks
        .iter()
        .filter_map(|edek| {
            if edek.has_cmk_edek() {
                Some(edek.cmk_edek())
            } else {
                None
            }
        })
        .collect_vec();
    if maybe_cmk_edeks.is_empty() {
        Err(AlloyError::DecryptError {
            msg: "No Saas Shield EDEK found.".to_string(),
        })
    } else {
        let kms_config_ids = maybe_cmk_edeks
            .iter()
            .map(|edek| edek.kmsConfigId as u32)
            .collect_vec();
        maybe_cmk_edeks
            .into_iter()
            .find(|edek| edek.kmsConfigId as u32 == kms_config_id)
            .ok_or_else(|| AlloyError::DecryptError {
                msg: format!(
                    "Document header malformed. Header key ID ({}) not found in EDEKs. Found: [{}]",
                    kms_config_id,
                    kms_config_ids.into_iter().join(",")
                ),
            })
    }
}

fn find_cmk_edek_v4(edeks: &[EdekWrapper]) -> Result<&EncryptedDek, AlloyError> {
    let maybe_edek_wrapper = edeks.iter().find(|edek| edek.has_cmk_edek());
    let cmk_edek = maybe_edek_wrapper
        .map(|edek| edek.cmk_edek())
        .ok_or_else(|| AlloyError::DecryptError {
            msg: "No Saas Shield EDEK found.".to_string(),
        })?;
    Ok(cmk_edek)
}

/// A function introduced to deal with the issue of EncryptedDeks from the TSP being mistakenly parsed as EncryptedDek.
/// This is mostly to allow compatibility with Cloaked Search from when this was an issue.
fn fix_encrypted_dek(
    cmk_edek: &cmk_edek::EncryptedDek,
) -> Result<cmk_edek::EncryptedDeks, AlloyError> {
    // Real kms config ids can't ever be 0, so if it is we parse it as an EncryptedDeks (which came from the tsp).
    // Then we put the tenant_id on each of them.
    let encrypted_deks = if cmk_edek.kmsConfigId == 0 {
        let bytes = cmk_edek.write_to_bytes().expect("Writing to bytes is safe");
        let encrypted_deks: cmk_edek::EncryptedDeks = Message::parse_from_bytes(bytes.as_ref())?;

        encrypted_deks
            .encryptedDeks
            .into_iter()
            .map(|mut edek| {
                edek.tenantId = cmk_edek.tenantId.clone();
                edek
            })
            .collect()
    } else {
        // If the kms_config_id is not 0, we assume this is a edek that was generated after the fix, so we can just pass it on.
        vec![cmk_edek.clone()]
    };
    Ok(cmk_edek::EncryptedDeks {
        encryptedDeks: encrypted_deks,
        ..Default::default()
    })
}

fn tsc_dek_to_encryption_key(dek: Vec<u8>) -> Result<EncryptionKey, AlloyError> {
    let bytes: [u8; 32] = dek.try_into().map_err(|_| AlloyError::InvalidKey {
        msg: "Invalid DEK".to_string(),
    })?;
    Ok(EncryptionKey(bytes))
}

pub fn generate_cmk_v4_doc_and_sign(
    edeks: Vec<EncryptedDek>,
    dek: EncryptionKey,
    tenant_id: &TenantId,
) -> Result<V4DocumentHeader, AlloyError> {
    let edek_wrappers = edeks
        .into_iter()
        .map(|mut edek| {
            edek.tenantId = tenant_id.0.clone().into();
            icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(icl_header_v4::v4document_header::edek_wrapper::Edek::CmkEdek(edek)),
                ..Default::default()
            }
        })
        .collect();

    Ok(ironcore_documents::v4::aes::create_signed_proto(
        edek_wrappers,
        dek,
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{EncryptedBytes, standard::EdekWithKeyIdHeader};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ironcore_documents::v5::key_id_header::{KeyId, KeyIdHeader};

    #[test]
    fn decompose_edek_header_makes_v3_for_invalid() {
        let encrypted_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![0u8])),
            document: Default::default(),
        };
        assert!(matches!(
            SaasShieldStandardClient::decompose_edek_header(encrypted_document.edek).unwrap(),
            EdekParts::V3(_)
        ));
    }

    #[test]
    fn get_document_header_and_edek_fails_for_wrong_type() {
        // This is a SaaS Shield Standard edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 1, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(bytes)),
            document: Default::default(),
        };

        assert!(matches!(
            SaasShieldStandardClient::decompose_edek_header(encrypted_doc.edek).unwrap_err(),
            AlloyError::InvalidInput { msg: _ }
        ));
    }

    #[test]
    fn get_document_header_and_edek_succeeds_for_good_header() {
        let edek = EncryptedDek {
            encryptedDekData: vec![1, 2, 3].into(),
            kmsConfigId: 1,
            tenantId: "tenant".into(),
            ..Default::default()
        };
        let v4_doc = generate_cmk_v4_doc_and_sign(
            vec![edek],
            EncryptionKey([1; 32]),
            &TenantId("tenant".to_string()),
        )
        .unwrap();
        let doc_bytes = v4_doc.write_to_bytes().unwrap();
        let final_bytes =
            KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(123))
                .put_header_on_document(doc_bytes);
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(final_bytes.to_vec())),
            document: Default::default(),
        };

        assert!(SaasShieldStandardClient::decompose_edek_header(encrypted_doc.edek).is_ok());
    }

    #[test]
    fn parse_old_v4_document_works() {
        let edek_and_header = EdekWithKeyIdHeader(EncryptedBytes(vec![
            10, 36, 10, 32, 64, 210, 116, 17, 37, 169, 25, 195, 73, 47, 59, 120, 34, 200, 205, 142,
            3, 154, 115, 130, 188, 198, 244, 161, 170, 163, 153, 254, 43, 237, 157, 167, 16, 1, 18,
            215, 1, 18, 212, 1, 18, 209, 1, 10, 192, 1, 10, 48, 63, 225, 165, 108, 33, 17, 151,
            119, 230, 185, 159, 203, 90, 67, 250, 185, 117, 54, 184, 68, 240, 128, 92, 176, 48, 35,
            52, 183, 27, 153, 15, 247, 241, 63, 221, 179, 246, 99, 9, 98, 221, 121, 156, 193, 220,
            197, 225, 126, 16, 255, 3, 24, 128, 5, 34, 12, 39, 49, 127, 75, 144, 142, 37, 173, 138,
            210, 233, 129, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165, 4, 100, 135, 130, 34, 228,
            127, 190, 188, 55, 199, 103, 184, 137, 98, 81, 5, 243, 99, 119, 248, 110, 101, 114,
            150, 161, 28, 100, 228, 110, 64, 123, 169, 222, 18, 73, 0, 220, 248, 78, 140, 39, 11,
            119, 244, 9, 168, 242, 190, 48, 191, 108, 152, 157, 29, 120, 97, 56, 118, 104, 45, 144,
            16, 245, 170, 9, 52, 111, 40, 22, 174, 185, 135, 102, 95, 142, 171, 180, 163, 118, 46,
            183, 105, 45, 137, 66, 170, 61, 49, 166, 47, 184, 99, 232, 86, 42, 73, 118, 87, 194,
            50, 103, 109, 176, 41, 144, 121, 250, 182, 16, 255, 3, 50, 12, 116, 101, 110, 97, 110,
            116, 45, 103, 99, 112, 45, 108,
        ]));
        let edek_parts = SaasShieldStandardClient::decompose_edek_header(edek_and_header).unwrap();
        assert!(matches!(edek_parts, EdekParts::V4(_)));
        let edek_bytes = edek_parts.get_edek_bytes().unwrap();
        let encrypted_deks: cmk_edek::EncryptedDeks =
            Message::parse_from_bytes(&edek_bytes).unwrap();
        assert_eq!(encrypted_deks.encryptedDeks.len(), 1);
        let encrypted_dek = encrypted_deks.encryptedDeks[0].clone();
        assert_eq!(encrypted_dek.kmsConfigId, 511);
        assert_eq!(encrypted_dek.tenantId.to_string(), "tenant-gcp-l");
    }

    #[test]
    fn parse_new_v5_document_works() {
        let edek_and_header = EdekWithKeyIdHeader(EncryptedBytes(vec![
            0, 0, 1, 255, 2, 0, 10, 36, 10, 32, 69, 182, 178, 20, 76, 114, 41, 199, 199, 34, 15,
            196, 128, 11, 147, 175, 190, 68, 241, 100, 46, 76, 139, 172, 5, 41, 226, 192, 84, 1,
            40, 31, 16, 1, 18, 212, 1, 18, 209, 1, 18, 206, 1, 10, 48, 212, 43, 219, 136, 159, 154,
            211, 225, 121, 20, 9, 189, 243, 102, 44, 168, 129, 150, 238, 97, 220, 248, 152, 117,
            48, 88, 45, 150, 114, 166, 74, 193, 252, 142, 29, 203, 233, 17, 14, 80, 34, 10, 236,
            100, 10, 206, 155, 123, 16, 255, 3, 24, 128, 5, 34, 12, 62, 97, 134, 143, 164, 152,
            252, 93, 101, 80, 51, 245, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165, 4, 100, 135, 130,
            34, 228, 127, 190, 188, 55, 199, 103, 184, 137, 98, 81, 5, 243, 99, 119, 248, 110, 101,
            114, 150, 161, 28, 100, 228, 110, 64, 123, 169, 222, 18, 73, 0, 220, 248, 78, 140, 39,
            11, 119, 244, 9, 168, 242, 190, 48, 191, 108, 152, 157, 29, 120, 97, 56, 118, 104, 45,
            144, 16, 245, 170, 9, 52, 111, 40, 22, 174, 185, 135, 102, 95, 142, 171, 180, 163, 118,
            46, 183, 105, 45, 137, 66, 170, 61, 49, 166, 47, 184, 99, 232, 86, 42, 73, 118, 87,
            194, 50, 103, 109, 176, 41, 144, 121, 250, 182, 16, 255, 3, 50, 12, 116, 101, 110, 97,
            110, 116, 45, 103, 99, 112, 45, 108,
        ]));
        let edek_parts = SaasShieldStandardClient::decompose_edek_header(edek_and_header).unwrap();
        assert!(matches!(edek_parts, EdekParts::V5(_, _)));
        let edek_bytes = edek_parts.get_edek_bytes().unwrap();
        let encrypted_deks: cmk_edek::EncryptedDeks =
            Message::parse_from_bytes(&edek_bytes).unwrap();
        assert_eq!(encrypted_deks.encryptedDeks.len(), 1);
        let encrypted_dek = encrypted_deks.encryptedDeks[0].clone();
        assert_eq!(encrypted_dek.kmsConfigId, 511);
        assert_eq!(encrypted_dek.tenantId.to_string(), "tenant-gcp-l");
    }

    #[test]
    fn parse_v3_document_works() {
        let edek = STANDARD.decode("CsABCjCkFe10OS/aiG6p9I0ijOirFq1nsRE8cPMog/bhOS0vYv5OCrYGZMSxOlo6dMJEYNgQ/wMYgAUiDEzjRFRtGVz1SRGWoip4CnYKcQokAKUEZIeCIuR/vrw3x2e4iWJRBfNjd/huZXKWoRxk5G5Ae6neEkkA3PhOjCcLd/QJqPK+ML9smJ0deGE4dmgtkBD1qgk0bygWrrmHZl+Oq7Sjdi63aS2JQqo9MaYvuGPoVipJdlfCMmdtsCmQefq2EP8D").unwrap();
        // This type isn't true, but it's what a caller would be creating if they had old EDEKs
        let liar_type_edek = EdekWithKeyIdHeader(EncryptedBytes(edek));
        let edek_parts = SaasShieldStandardClient::decompose_edek_header(liar_type_edek).unwrap();
        assert!(matches!(edek_parts, EdekParts::V3(_)));
        let edek_bytes = edek_parts.get_edek_bytes().unwrap();
        let encrypted_deks: cmk_edek::EncryptedDeks =
            Message::parse_from_bytes(&edek_bytes).unwrap();
        assert_eq!(encrypted_deks.encryptedDeks.len(), 1);
        let encrypted_dek = encrypted_deks.encryptedDeks[0].clone();
        assert_eq!(encrypted_dek.kmsConfigId, 511);
        // This EDEK came from TSC-java, where we weren't setting tenant IDs
        assert_eq!(encrypted_dek.tenantId.to_string(), "");
    }
}
