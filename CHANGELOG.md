## 0.16.0

- Dependency updates.
- Added streaming encryption and decryption for standard and standard-attached documents.

### Streaming

New methods on `StandardDocumentOps`:

- `create_streaming_encryptor(metadata)` returns a `StreamingStandardEncryptor`. Call `edek()` to get the EDEK to store alongside the output, `encrypt_chunk(bytes)` for each chunk of plaintext, and `finish()` to flush the final bytes and the authentication tag.
- `create_streaming_decryptor(edek, metadata)` returns a `StreamingStandardDecryptor`. Feed the encrypted document with `decrypt_chunk(bytes)` and call `finish()` once at the end to verify authentication.

New methods on `StandardAttachedDocumentOps`:

- `create_streaming_attached_encryptor(metadata)` returns a `StreamingStandardAttachedEncryptor`. The EDEK is written inline at the front of the stream, so there is nothing separate to store. Use `encrypt_chunk(bytes)` and `finish()` as above.
- `create_streaming_attached_decryptor(metadata)` returns a `StreamingStandardAttachedDecryptor`. Feed the attached document to `decrypt_chunk(bytes)` exactly as it comes off the wire - the inline EDEK and IV are parsed off the front of the stream for you - and call `finish()` at the end.

Things to know:

- **The streaming output is byte-identical to the one-shot format.** A document encrypted with streaming can be decrypted with the one-shot `decrypt`, and a one-shot-encrypted document can be decrypted with streaming, in any combination.
- **The constructors are async; the chunk methods are synchronous** (CPU-only) — the constructor does the DEK acquisition (a TSP call for SaaS Shield). The one exception is `StreamingStandardAttachedDecryptor`: its `decrypt_chunk`/`finish` are **async**, because the EDEK embedded in the stream must be unwrapped (a TSP call for SaaS Shield) before any ciphertext can be decrypted. In each language this is the usual async shape (Kotlin `suspend`, Python `async`, Java `CompletableFuture`).
- **⚠️ Streaming decryption releases UNVERIFIED plaintext.** The authentication tag is at the very end of the stream, so `decrypt_chunk` returns plaintext _before_ it can be verified. If `finish()` returns an error, every chunk already produced was never authenticated and may have been attacker-controlled. Callers that act on decrypted chunks as they arrive **must be able to roll those effects back** if `finish()` fails — for example, write decrypted chunks to a temporary file and only commit it after `finish()` succeeds. This is the central risk of the API.
- **Legacy format:** SaaS Shield standard streaming honors `legacy_tsc_write_format` exactly like one-shot `encrypt`. With it enabled, streamed standard documents are written in the legacy V3 (`tenant-security-client-*`) format; streaming decryption reads both the current V5 format and the legacy V3 format. Standard-attached has no legacy format and always uses V5.
- **Scope:** streaming is offered for standard and standard-attached only. Deterministic and vector encryption do not support it.
- New `streaming-roundtrip` examples show file-to-file streaming in Rust (`examples/rust/standalone/streaming-roundtrip`) and Python (`examples/python/standalone/streaming-roundtrip.py`), including the temp-file-and-commit pattern for the rollback contract above.

## 0.15.2

- Fix a check on API key that was too strict

## 0.15.1

- Fix to Rust doc.rs build.

## 0.15.0

- Dependency updates
- Added `legacy_tsc_write_format` option to `SaasShieldConfiguration`. When enabled, standard encryption writes in the legacy `tenant-security-client-*` V3 data format, allowing in-place migration from TSC SDKs to alloy without changing the encrypted data format. Only affects `StandardDocumentOps`. Attached, deterministic, and vector encryption are unaffected. See [the TSC-> Alloy migration guide](./TSC_ALLOY_MIGRATION_GUIDE.md)` for details.

### Breaking Changes
- Update to uniffi-bindgen-java 0.4.0, uniffi 0.31.0.
  - `List<Float>` -> `float[]`, same for all other primitive lists
  - Switched from JNA to FFM, which requires [enabling native acces](https://docs.oracle.com/en/java/javase/25/core/restricted-methods.html)
  - Java 22+ required
- `StandardDocumentOps::get_searchable_edek_prefix` will not match V3 EDEKs, but may still be useful if the store contains V5 data alongside V3 data.
- `SaasShieldConfiguration::new` and `new_with_scaling_factor` have a new `legacy_tsc_write_format: bool` parameter (defaults to `false` in languages with defaults).
- `encrypt_with_existing_edek` now matches its field format to the provided EDEK's format, ignoring the `legacy_tsc_write_format` setting. To upgrade a document from V3 to V5, first rekey the EDEK via `rekey_edeks`.

## 0.14.0

- Dependency updates

### Breaking Changes

- All SaaSShield configs now require an `allow_insecure_http` setting, which specifies whether or not the connection to the TSP must be via HTTPS. This defaults to `false` in languages with defaults.

## 0.13.1

- Fix a bug in SaaS Shield clients using the default HttpClient that would cause TSP requests to fail with a bad auth header.

## 0.13.0

- Dependency updates
- Added a `new_seeded_for_testing` constructor for `StandaloneConfiguration` which allows for testing with deterministic known values. DO NOT USE IN PRODUCTION CODE.

### Breaking Changes

- Default constructors for `VectorSecret` and `SaasShieldConfiguration` now set the scaling factor to 1. If you want to continuing using the scaling factor you can call the `new_with_scaling_factor` on the respective classes.

## 0.12.0

- Dependency updates
- Async functionality now runs fully in the host language's async runtime; there is no longer sometimes a Tokio (a Rust async runtime) runtime created to manage async tasks.

### Breaking Changes

- Updated SaaS Shield Clients to take a native http client as an argument. The client must implement HttpClient, which requires only a `postJson` function. See tests in the various languages for example implementations.

## 0.11.2

- Dependency updates
- Dropped build for Mac OS 12 and replaced it with Mac OS 13.

## 0.11.1

Breaking changes:

- Dropped support for Python 3.8
- Reworked several type aliases into newtype structs. In Rust this will require creating structs, but Python and Kotlin are unaffected.
- Renamed `StandaloneAttachedStandardClient` to `StandaloneStandardAttachedClient`.
- Changed Standard Attached `get_searchable_edek_prefix` to be synchronous.
- Changed several constructors to require keyword arguments.

Other changes:

- Added Java bindings, `ironcore-alloy-java`
- Added batch functionality to all SDK traits.
- Fixed a bug where Standard Attached wasn't accessible for SaaS Shield clients.
- Added rekey functionality for standard_attached data.

## 0.10.2

- Added SaaS Shield security events
- Added SaaS Shield vector rotation
- Added support for standard attached documents
- Added backwards compatibility with TSC and Cloaked Search libraries
- Reworked AlloyError to allow easier matching on error responses

## 0.9.0

Initial release of Alloy. This library is intended to eventually replace the Tenant Security Client libraries, and include additional functionality. Right now this includes:

- our standard (probabilistic, fully random) encryption
- deterministic encryption
- Cloaked AI vector encryption

All three of these support standalone and SaaS Shield modes in this SDK.

Notable features coming soon:

- SaaS Shield security events
- backwards compatibility with TSC libraries
- batch APIs
- rekey and rotate functionality

### Compatibility

Requires TSP 4.12.0+.
