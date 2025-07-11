// Standard standalone works for V4 and V5 documents. There is no suport for V3 since Standalone wasn't
// available in V3.
use super::config::{StandaloneConfiguration, StandardSecrets};
use crate::errors::AlloyError;
use crate::standard::{
    EdekWithKeyIdHeader, EncryptedDocument, EncryptedDocuments, PlaintextDocument,
    PlaintextDocumentWithEdek, PlaintextDocuments, PlaintextDocumentsWithEdeks,
    RekeyEdeksBatchResult, StandardDecryptBatchResult, StandardDocumentOps,
    StandardEncryptBatchResult, decrypt_document_core, encrypt_document_core, encrypt_map,
    verify_sig,
};
use crate::util::{OurReseedingRng, hash256, perform_batch_action};
use crate::{
    AlloyMetadata, DocumentId, Secret, TenantId,
    alloy_client_trait::{AlloyClient, DecomposedHeader},
};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::v5::key_id_header::{
    EdekType, KeyId, PayloadType, get_prefix_bytes_for_search,
};
use ironcore_documents::{icl_header_v4, v5};
use itertools::Itertools;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct StandaloneStandardClient {
    config: Arc<StandardSecrets>,
    rng: Arc<Mutex<OurReseedingRng>>,
}
impl StandaloneStandardClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        Self {
            config: config.standard.clone(),
            rng: crate::util::create_rng_maybe_seeded(config.test_rng_seed),
        }
    }

    fn get_current_secret_and_id(&self) -> Result<(u32, &Secret), AlloyError> {
        let primary_secret_id =
            self.config
                .primary_secret_id
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: "No primary secret exists in the standard configuration".to_string(),
                })?;
        self.config
            .secrets
            .get(&primary_secret_id)
            .map(|secret| (primary_secret_id, secret))
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: "Primary secret id not found in secrets map".to_string(),
            })
    }

    /// Encrypt all the fields from the document using a single `key`. A DEK will be generated and encrypted using a derived key.
    /// Each field of the document will be encrypted separately using a random iv and this single generated dek.
    fn encrypt_sync(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let (secret_id, secret) = self.get_current_secret_and_id()?;
        let per_tenant_kek = derive_aes_encryption_key(&secret.secret, &metadata.tenant_id);
        let (aes_dek, v4_doc) = v5::aes::generate_aes_edek_and_sign(
            self.rng.clone(),
            per_tenant_kek,
            None,
            secret_id.to_string().as_str(),
        )?;
        encrypt_document_core(
            plaintext_document.0,
            self.rng.clone(),
            aes_dek,
            self.create_key_id_header(secret_id),
            v4_doc,
        )
    }

    /// Decrypt the document DEK, then use it to decrypt the document.
    fn decrypt_sync(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError> {
        let dek = self.decrypt_document_dek(
            encrypted_document.edek,
            &self.config.secrets,
            &metadata.tenant_id,
        )?;
        decrypt_document_core(encrypted_document.document, dek).map(PlaintextDocument)
    }

    /// Given the edek, the secrets and the metadata, try to decrypt the per tenant_kek using the secret.
    /// Then decrypt the per document EncryptionKey using that per tenant kek.
    fn decrypt_document_dek(
        &self,
        edek: EdekWithKeyIdHeader,
        config_secrets: &HashMap<u32, Secret>,
        tenant_id: &TenantId,
    ) -> Result<EncryptionKey, AlloyError> {
        let DecomposedHeader {
            key_id,
            remaining_bytes: edek_bytes,
        } = self.decompose_key_id_header(edek.0)?;

        // Key id should never be 0. If it is we'll try all the keys we have.
        let secrets = if key_id.0 == 0 {
            config_secrets.values().collect_vec()
        } else {
            let secret =
                config_secrets
                    .get(&key_id.0)
                    .ok_or_else(|| AlloyError::InvalidConfiguration {
                        msg: format!(
                            "Provided secret id `{}` does not exist in the standard configuration.",
                            &key_id.0
                        ),
                    })?;
            vec![secret]
        };

        let attempt_decrypt = |secret: &Secret| {
            let v4_document = crate::util::v4_proto_from_bytes(&edek_bytes)?;
            // For standalone we want to try out the normal derivation first.
            decrypt_aes_edek(
                &derive_aes_encryption_key(&secret.secret, tenant_id),
                &v4_document,
            )
            .or_else(|_| {
                //If normal derivation doesn't work, we'll try our legacy derivation that was used in cloaked search.
                decrypt_aes_edek(
                    &derive_aes_encryption_key_legacy(&secret.secret, tenant_id),
                    &v4_document,
                )
            })
        };

        secrets
            .into_iter()
            .map(attempt_decrypt)
            .find_or_first(|result| result.is_ok())
            .unwrap_or(Err(AlloyError::InvalidConfiguration {
                msg: "No secret could be found to decrypt".to_string(),
            }))
    }

    /// Synchronous helper function for `encrypt_with_existing_edek`.
    /// Encrypt a document with the provided metadata. The document must be a map from field identifiers to plaintext
    /// bytes, and the same metadata must be provided when decrypting the document.
    /// The provided EDEK will be decrypted and used to encrypt each field. This is useful when updating some fields
    /// of the document.
    fn encrypt_with_existing_edek_sync(
        &self,
        plaintext_document: PlaintextDocumentWithEdek,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let dek = self.decrypt_document_dek(
            plaintext_document.edek.clone(),
            &self.config.secrets,
            &metadata.tenant_id,
        )?;
        let encrypted_document: HashMap<_, _> =
            encrypt_map(plaintext_document.document.0, self.rng.clone(), dek)?;
        Ok(EncryptedDocument {
            edek: plaintext_document.edek,
            document: encrypted_document,
        })
    }
}

impl AlloyClient for StandaloneStandardClient {
    fn get_edek_type(&self) -> EdekType {
        EdekType::Standalone
    }

    fn get_payload_type(&self) -> PayloadType {
        PayloadType::StandardEdek
    }
}

#[uniffi::export]
#[async_trait::async_trait]
impl StandardDocumentOps for StandaloneStandardClient {
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
        self.encrypt_sync(plaintext_document, metadata)
    }

    /// Encrypt each of the provided documents with the provided metadata.
    /// Note that because only a single metadata value is passed, each document will be encrypted to the same tenant.
    async fn encrypt_batch(
        &self,
        plaintext_documents: PlaintextDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardEncryptBatchResult, AlloyError> {
        let encrypt_document = |plaintext_document| self.encrypt_sync(plaintext_document, metadata);
        Ok(perform_batch_action(plaintext_documents.0, encrypt_document).into())
    }

    /// Decrypt a document that was encrypted with the provided metadata. The document must have been encrypted with one
    /// of the `StandardDocumentOps.encrypt` functions. The result contains a map from field identifiers to decrypted
    /// bytes.
    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError> {
        self.decrypt_sync(encrypted_document, metadata)
    }

    /// Decrypt each of the provided documents with the provided metadata.
    /// Note that because the metadata is shared between the documents, they all must correspond to the
    /// same tenant ID.
    async fn decrypt_batch(
        &self,
        encrypted_documents: EncryptedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardDecryptBatchResult, AlloyError> {
        let decrypt_document = |encrypted_document| self.decrypt_sync(encrypted_document, metadata);
        Ok(perform_batch_action(encrypted_documents.0, decrypt_document).into())
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
        let rekey_edek = |edek: EdekWithKeyIdHeader| {
            let dek = self.decrypt_document_dek(edek, &self.config.secrets, &metadata.tenant_id)?;
            let (current_secret_id, current_secret) = self.get_current_secret_and_id()?;
            let encryption_key =
                derive_aes_encryption_key(&current_secret.secret, parsed_new_tenant_id);
            let (_, v4_doc) = v5::aes::generate_aes_edek_and_sign(
                self.rng.clone(),
                encryption_key,
                Some(dek),
                current_secret_id.to_string().as_str(),
            )?;
            Ok(EdekWithKeyIdHeader::new(
                self.create_key_id_header(current_secret_id),
                v4_doc,
            ))
        };
        Ok(perform_batch_action(edeks, rekey_edek).into())
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
        self.encrypt_with_existing_edek_sync(plaintext_document, metadata)
    }

    /// Encrypt multiple documents with the provided metadata.
    /// The provided EDEKs will be decrypted and used to encrypt each corresponding document's fields.
    /// This is useful when updating some fields of the document.
    async fn encrypt_with_existing_edek_batch(
        &self,
        plaintext_documents: PlaintextDocumentsWithEdeks,
        metadata: &AlloyMetadata,
    ) -> Result<StandardEncryptBatchResult, AlloyError> {
        let encrypt =
            |plaintext_document| self.encrypt_with_existing_edek_sync(plaintext_document, metadata);
        Ok(perform_batch_action(plaintext_documents.0, encrypt).into())
    }

    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
        get_prefix_bytes_for_search(ironcore_documents::v5::key_id_header::KeyIdHeader::new(
            self.get_edek_type(),
            self.get_payload_type(),
            KeyId(id as u32),
        ))
        .into()
    }
}

/// Try to find the aes edek in the V4 header and decrypt the aes edek using the provided kek.
/// Will fail if the signature verification fails, decryption fails or if an aes edek could not be found.
pub(crate) fn decrypt_aes_edek(
    kek: &EncryptionKey,
    header: &icl_header_v4::V4DocumentHeader,
) -> Result<EncryptionKey, AlloyError> {
    let maybe_edek_wrapper = header
        .signed_payload
        .edeks
        .as_slice()
        .iter()
        .find(|edek| edek.has_aes_256_gcm_edek());
    let aes_edek = maybe_edek_wrapper
        .map(|edek| edek.aes_256_gcm_edek())
        .ok_or_else(|| AlloyError::DecryptError {
            msg: "No AES EDEK found.".to_string(),
        })?;
    let aes_dek = v5::aes::decrypt_aes_edek(kek, aes_edek)?;
    verify_sig(aes_dek, header)?;
    Ok(aes_dek)
}

/// Derives an encryption key for the given tenant and secret. Note that this is the same way that it's done in cloaked search for compatibility
/// with edeks from there.
pub(crate) fn derive_aes_encryption_key<K: AsRef<[u8]>>(
    derivation_key: &K,
    tenant_id: &TenantId,
) -> EncryptionKey {
    let resulting_bytes: String =
        Itertools::intersperse([tenant_id.0.as_str(), "encryption_key"].into_iter(), "-").collect();
    EncryptionKey(hash256(derivation_key.as_ref(), resulting_bytes))
}

// This is a derivation that was used in cloaked search. It's not used anymore, but is here for the decryption
// of cloaked search data.
fn derive_aes_encryption_key_legacy<K: AsRef<[u8]>>(
    key: &K,
    tenant_id: &TenantId,
) -> EncryptionKey {
    let extra_array = vec!["encryption_key".as_bytes()];
    let hkdf_key = hkdf::Salt::new(hkdf::HKDF_SHA256, key.as_ref());
    let prk = hkdf_key.extract(tenant_id.0.as_bytes());
    let okm = prk.expand(&extra_array, hkdf::HKDF_SHA256).unwrap(); //unwrap is safe since len is based on the same algorithm we're using.
    {
        let mut buffer = [0u8; SHA256_OUTPUT_LEN];
        //unwrap is safe since it can only fail if "the requested output length is larger than 255
        //times the size of the digest algorithm's output."
        okm.fill(&mut buffer).unwrap();
        EncryptionKey(buffer)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{EncryptedBytes, FieldId, Secret};
    use crate::{standard::EdekWithKeyIdHeader, util::create_test_seeded_rng};
    use ironcore_documents::v5::key_id_header::{self, EdekType, KeyId, PayloadType};

    fn default_client() -> StandaloneStandardClient {
        new_client(Some(1))
    }

    pub(crate) fn new_client(primary_secret_id: Option<u32>) -> StandaloneStandardClient {
        StandaloneStandardClient {
            config: Arc::new(StandardSecrets {
                primary_secret_id,
                secrets: [
                    (
                        1u32,
                        Secret {
                            secret: [0u8; 32].to_vec(),
                        },
                    ),
                    (
                        2u32,
                        Secret {
                            secret: [1u8; 32].to_vec(),
                        },
                    ),
                    (
                        3,
                        Secret {
                            // This is from cloaked search tests.
                            secret: "super secret key".as_bytes().to_vec(),
                        },
                    ),
                ]
                .into(),
            }),
            rng: create_test_seeded_rng(100),
        }
    }
    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let encrypted = client
            .encrypt(PlaintextDocument(document.clone()), &metadata)
            .await
            .unwrap();
        let (key_id_header, _) =
            key_id_header::decode_version_prefixed_value(encrypted.edek.0.0.clone().into())
                .unwrap();
        assert_eq!(key_id_header.key_id, KeyId(1));
        assert_eq!(key_id_header.edek_type, EdekType::Standalone);
        assert_eq!(key_id_header.payload_type, PayloadType::StandardEdek);
        let decrypted = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(decrypted.0, document);
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_with_existing_edek_roundtrip() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let document2: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 4].into())].into();
        let encrypted = client
            .encrypt(PlaintextDocument(document.clone()), &metadata)
            .await
            .unwrap();
        let encrypted_2 = client
            .encrypt_with_existing_edek(
                PlaintextDocumentWithEdek::new(
                    encrypted.edek.clone(),
                    PlaintextDocument(document2.clone()),
                ),
                &metadata,
            )
            .await
            .unwrap();
        let decrypted = client
            .decrypt(encrypted_2.clone(), &metadata)
            .await
            .unwrap();
        assert_eq!(encrypted.edek, encrypted_2.edek);
        assert_eq!(decrypted.0, document2);
        Ok(())
    }

    #[tokio::test]
    async fn rekey_edek_roundtrip() {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let encrypted = client
            .encrypt(PlaintextDocument(document.clone()), &metadata)
            .await
            .unwrap();
        let mut rekeyed = client
            .rekey_edeks(
                [(DocumentId("foo".to_string()), encrypted.edek.clone())].into(),
                &metadata,
                None,
            )
            .await
            .unwrap();
        assert!(rekeyed.failures.is_empty());
        assert!(
            rekeyed
                .successes
                .contains_key(&DocumentId("foo".to_string()))
        );
        let new_edek = rekeyed
            .successes
            .remove(&DocumentId("foo".to_string()))
            .unwrap();
        assert_ne!(encrypted.edek, new_edek);
        let remade_document = EncryptedDocument {
            edek: new_edek,
            document: encrypted.document,
        };
        let decrypted = client.decrypt(remade_document, &metadata).await.unwrap();
        assert_eq!(decrypted.0, document);
    }

    #[tokio::test]
    async fn rekey_edek_new_current() {
        // Manually creating client so it doesn't have secret 2.
        let client = StandaloneStandardClient {
            config: Arc::new(StandardSecrets {
                primary_secret_id: Some(1),
                secrets: [(
                    1,
                    Secret {
                        secret: [0; 32].to_vec(),
                    },
                )]
                .into(),
            }),
            rng: create_test_seeded_rng(100),
        };
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let encrypted = client
            .encrypt(PlaintextDocument(document.clone()), &metadata)
            .await
            .unwrap();
        let new_client = new_client(Some(2));
        let mut rekeyed = new_client
            .rekey_edeks(
                [(DocumentId("foo".to_string()), encrypted.edek.clone())].into(),
                &metadata,
                None,
            )
            .await
            .unwrap();
        assert!(rekeyed.failures.is_empty());
        assert!(
            rekeyed
                .successes
                .contains_key(&DocumentId("foo".to_string()))
        );
        let new_edek = rekeyed
            .successes
            .remove(&DocumentId("foo".to_string()))
            .unwrap();
        assert_ne!(encrypted.edek, new_edek);
        let remade_document = EncryptedDocument {
            edek: new_edek,
            document: encrypted.document,
        };
        // This fails because the original client doesn't have key 2, which is what the document
        // was rekeyed to.
        let decrypt_err = client
            .decrypt(remade_document.clone(), &metadata)
            .await
            .unwrap_err();
        assert!(decrypt_err.to_string().contains("id `2` does not exist"));
        let decrypted = new_client
            .decrypt(remade_document, &metadata)
            .await
            .unwrap();
        assert_eq!(decrypted.0, document);
    }

    #[tokio::test]
    async fn decrypt_missing_key_from_config() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let encrypted = EncryptedDocument {
            //The header having a `4` means that the edek is for key id 4.
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![0, 0, 0, 4, 130, 0])),
            document: HashMap::new(),
        };
        let error = client.decrypt(encrypted, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration {
                msg: "Provided secret id `4` does not exist in the standard configuration."
                    .to_string()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_missing_primary() -> Result<(), AlloyError> {
        let client = new_client(None);
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let error = client
            .encrypt(PlaintextDocument(document), &metadata)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration {
                msg: "No primary secret exists in the standard configuration".to_string()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_primary_not_found() -> Result<(), AlloyError> {
        // This id isn't in the config map.
        let client = new_client(Some(1000));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let error = client
            .encrypt(PlaintextDocument(document), &metadata)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration {
                msg: "Primary secret id not found in secrets map".to_string()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_id_not_primary() -> Result<(), AlloyError> {
        //The edek below is for key_id 1, setting primary to 2 in the sdk.
        let client = new_client(Some(2));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![
                0, 0, 0, 1, 130, 0, 10, 36, 10, 32, 63, 209, 198, 171, 21, 208, 189, 114, 147, 46,
                77, 51, 5, 205, 148, 219, 103, 230, 206, 111, 139, 227, 209, 247, 100, 74, 55, 178,
                42, 107, 148, 237, 16, 1, 18, 71, 18, 69, 26, 67, 10, 12, 248, 21, 21, 9, 41, 0,
                71, 124, 244, 209, 252, 151, 18, 48, 77, 53, 19, 139, 40, 178, 7, 81, 160, 95, 18,
                209, 6, 53, 112, 39, 222, 52, 235, 151, 227, 69, 139, 208, 207, 8, 32, 92, 4, 28,
                59, 126, 89, 87, 96, 177, 145, 45, 167, 75, 142, 49, 14, 249, 71, 29, 207, 70, 26,
                1, 49,
            ])),
            document: [(
                FieldId("hi".to_string()),
                EncryptedBytes(vec![
                    0, 73, 82, 79, 78, 7, 10, 168, 250, 84, 170, 243, 140, 53, 47, 99, 212, 184,
                    119, 142, 12, 136, 196, 155, 120, 225, 188, 254, 66, 143, 227, 183, 50, 78, 0,
                    50,
                ]),
            )]
            .into(),
        };
        let plaintext = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(plaintext.0, document);
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_id_zero() -> Result<(), AlloyError> {
        //The edek below is for key_id 0, setting primary to 2 in the sdk.
        let client = new_client(Some(2));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [(FieldId("hi".to_string()), vec![1, 2, 3].into())].into();
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![
                0, 0, 0, 0, 130, 0, 10, 36, 10, 32, 63, 209, 198, 171, 21, 208, 189, 114, 147, 46,
                77, 51, 5, 205, 148, 219, 103, 230, 206, 111, 139, 227, 209, 247, 100, 74, 55, 178,
                42, 107, 148, 237, 16, 1, 18, 71, 18, 69, 26, 67, 10, 12, 248, 21, 21, 9, 41, 0,
                71, 124, 244, 209, 252, 151, 18, 48, 77, 53, 19, 139, 40, 178, 7, 81, 160, 95, 18,
                209, 6, 53, 112, 39, 222, 52, 235, 151, 227, 69, 139, 208, 207, 8, 32, 92, 4, 28,
                59, 126, 89, 87, 96, 177, 145, 45, 167, 75, 142, 49, 14, 249, 71, 29, 207, 70, 26,
                1, 49,
            ])),
            document: [(
                FieldId("hi".to_string()),
                EncryptedBytes(vec![
                    0, 73, 82, 79, 78, 7, 10, 168, 250, 84, 170, 243, 140, 53, 47, 99, 212, 184,
                    119, 142, 12, 136, 196, 155, 120, 225, 188, 254, 66, 143, 227, 183, 50, 78, 0,
                    50,
                ]),
            )]
            .into(),
        };
        let plaintext = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(plaintext.0, document);
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_failure_with_zero_key_id() -> Result<(), AlloyError> {
        //The edek below is for key_id 0, setting primary to 2 in the sdk.
        let client = new_client(Some(2));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![
                0, 0, 0, 0, 130, 0, 10, 36, 10, 32, 63, 209, 198, 171, 21, 208, 189, 114, 147, 46,
                77, 51, 5, 205, 148, 219, 103, 230, 206, 111, 139, 227, 209, 247, 100, 74, 55, 178,
                42, 107, 148, 237, 16, 1, 18, 71, 18, 69, 26, 67, 10, 12, 248, 21, 21, 9, 41, 0,
                71, 124, 244, 209, 252, 151, 18, 48, 77, 53, 19, 139, 40, 178, 7, 81, 160, 95, 18,
                209, 6, 53, 112, 39, 222, 52, 235, 151, 227, 69, 139, 208, 207, 8, 32, 92, 4, 28,
                59, 126, 89, 87,
            ])),
            document: [(
                FieldId("hi".to_string()),
                EncryptedBytes(vec![
                    0, 73, 82, 79, 78, 7, 10, 168, 250, 84, 170, 243, 140, 53, 47, 99, 212, 184,
                    119, 142, 12, 136, 196, 155, 120, 225, 188, 254, 66, 143, 227, 183, 50, 78, 0,
                    50,
                ]),
            )]
            .into(),
        };
        let error = client.decrypt(encrypted, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::ProtobufError {
                msg: "Unexpected EOF".to_string()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_edek_type_not_match() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(vec![0, 0, 0, 1, 0, 0])),
            document: HashMap::new(),
        };
        let error = client.decrypt(encrypted, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidInput{ msg:
                "The data indicated that this was not a Standalone Standard EDEK wrapped value. Found: SaaS Shield, Deterministic Field"
                    .to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn get_searchable_edek_prefix_works() {
        let client = default_client();
        let result = client.get_searchable_edek_prefix(100);
        assert_eq!(result, vec![0, 0, 0, 100, 130, 0]);
    }
}
