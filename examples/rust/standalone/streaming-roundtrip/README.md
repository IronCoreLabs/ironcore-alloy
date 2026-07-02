# Streaming Round-Trip Example

Streams a file through standard encryption to disk and back, in 64 KiB chunks, so the whole file
never has to be held in memory at once.

```bash
export STANDALONE_SECRET='R8xfozIf4T4WZkERh1rpN4mdIe7bL2vK'
cargo run
```

This should produce output like:

```text
Encrypted plaintext.bin -> plaintext.bin.enc (EDEK stored in plaintext.bin.edek)
Decrypted plaintext.bin.enc -> decrypted.bin
Success: decrypted.bin matches plaintext.bin (5242880 bytes).
```

## What it does

1. Creates a 5 MiB sample `plaintext.bin` if one isn't already present.
2. **Streaming encrypt**: reads `plaintext.bin` in chunks, feeds each through `encrypt_chunk`, and
   writes the ciphertext to `plaintext.bin.enc`, finishing with `finish()` (which appends the
   authentication tag). The EDEK (Encrypted Data Encryption Key, required to decrypt) is written
   separately to `plaintext.bin.edek`.
3. **Streaming decrypt**: reads `plaintext.bin.enc` in chunks back through `decrypt_chunk`, then
   verifies the authentication tag with `finish()`, producing `decrypted.bin`.
4. Confirms `decrypted.bin` is identical to the original.

The streamed output is byte-identical to the one-shot format, so `plaintext.bin.enc` could just as
well be decrypted with the one-shot `decrypt` API (and a one-shot–encrypted document can be decrypted
with the streaming API).

## ⚠️ The release-of-unverified-plaintext contract

Streaming decryption returns plaintext chunks **before** the authentication tag is verified — the tag
is at the very end of the stream, so there is no way to check it until everything has been read. If
`finish()` returns an error, every chunk already produced was never authenticated and may have been
attacker-controlled.

This example handles that the safe way: it writes decrypted chunks to a temporary file and only
renames it into place **after** `finish()` succeeds. If verification fails, the temp file is deleted,
so unverified plaintext is never exposed as the real output. Any program that processes streamed
plaintext as it arrives must be able to roll back its effects the same way.

## Attached streaming

This example uses standard (detached) encryption, where the EDEK is stored separately. There is also
a standard-*attached* streaming API (`create_streaming_attached_encryptor` /
`create_streaming_attached_decryptor`) that writes the EDEK inline at the front of the stream, so
there is nothing separate to store — you just feed the whole blob back in to decrypt.
