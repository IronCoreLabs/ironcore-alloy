use crate::errors::AlloyError;
use crate::standard::{
    decrypt_document_core, encrypt_document_core, encrypt_map, verify_sig, EdekWithKeyIdHeader,
    EncryptedDocument, PlaintextDocument, PlaintextDocumentWithEdek, RekeyEdeksBatchResult,
    StandardDocumentOps,
};
use crate::util::{collection_to_batch_result, get_rng, hash256, OurReseedingRng};
use crate::{alloy_client_trait::AlloyClient, AlloyMetadata, Secret, TenantId};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::v5::key_id_header::{EdekType, KeyId, PayloadType};
use ironcore_documents::{icl_header_v4, v5};
use itertools::Itertools;
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::config::{StandaloneConfiguration, StandardSecrets};

#[derive(uniffi::Object)]
pub struct StandaloneStandardClient {
    config: Arc<StandardSecrets>,
    rng: Arc<Mutex<OurReseedingRng>>,
}
impl StandaloneStandardClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        Self {
            config: config.standard.clone(),
            rng: crate::util::create_reseeding_rng(),
        }
    }

    fn get_current_secret_and_id(&self) -> Result<(u32, &Secret), AlloyError> {
        let primary_secret_id = self.config.primary_secret_id.ok_or_else(|| {
            AlloyError::InvalidConfiguration(
                "No primary secret exists in the standard configuration".to_string(),
            )
        })?;
        self.config
            .secrets
            .get(&primary_secret_id)
            .map(|secret| (primary_secret_id, secret))
            .ok_or_else(|| {
                AlloyError::InvalidConfiguration(
                    "Primary secret id not found in secrets map".to_string(),
                )
            })
    }

    /// Encrypt all the fields from the document using a single `key`. A DEK will be generated and encrypted using a derived key.
    /// Each field of the document will be encrypted separately using a random iv and this single generated dek.
    pub(crate) fn encrypt_document<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
        incoming_key: &[u8],
        document: HashMap<String, U>,
        key_id: KeyId,
        rng: Arc<Mutex<R>>,
        tenant_id: &TenantId,
    ) -> Result<EncryptedDocument, AlloyError> {
        let per_tenant_kek = derive_aes_encryption_key(&incoming_key, tenant_id);
        let (aes_dek, v4_doc) = v5::aes::generate_aes_edek_and_sign(
            &mut *get_rng(&rng),
            per_tenant_kek,
            None,
            key_id.0.to_string().as_str(),
        )?;
        encrypt_document_core(
            document,
            rng,
            aes_dek,
            Self::create_key_id_header(key_id.0),
            v4_doc,
        )
    }

    /// Given the edek, the secrets and the metadata, try to decrypt the per tenant_kek using the secret.
    /// Then decrypt the per document EncryptionKey using that per tenant kek.
    fn decrypt_document_dek(
        edek: EdekWithKeyIdHeader,
        config_secrets: &HashMap<u32, Secret>,
        tenant_id: &TenantId,
    ) -> Result<EncryptionKey, AlloyError> {
        let (key_id, edek_bytes) = Self::decompose_key_id_header(edek.0)?;
        let secret = config_secrets.get(&key_id.0).ok_or_else(|| {
            AlloyError::InvalidConfiguration(format!(
                "Provided secret id `{}` does not exist in the standard configuration.",
                &key_id.0
            ))
        })?;
        let per_tenant_kek = derive_aes_encryption_key(&secret.secret, tenant_id);
        let v4_document = Message::parse_from_bytes(&edek_bytes[..])
            .map_err(|e| AlloyError::DecryptError(e.to_string()))?;
        decrypt_aes_edek(&per_tenant_kek, &v4_document)
    }
}

impl AlloyClient for StandaloneStandardClient {
    fn get_edek_type() -> EdekType {
        EdekType::Standalone
    }

    fn get_payload_type() -> PayloadType {
        PayloadType::StandardEdek
    }
}

#[uniffi::export]
impl StandardDocumentOps for StandaloneStandardClient {
    async fn encrypt(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let (secret_id, secret) = self.get_current_secret_and_id()?;
        let encrypted_doc = Self::encrypt_document(
            &secret.secret,
            plaintext_document,
            KeyId(secret_id),
            self.rng.clone(),
            &metadata.tenant_id,
        )?;
        Ok(encrypted_doc)
    }

    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError> {
        let dek = Self::decrypt_document_dek(
            encrypted_document.edek,
            &self.config.secrets,
            &metadata.tenant_id,
        )?;
        decrypt_document_core(encrypted_document.document, dek)
    }

    async fn rekey_edeks(
        &self,
        edeks: HashMap<String, EdekWithKeyIdHeader>,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyEdeksBatchResult, AlloyError> {
        let parsed_new_tenant_id = new_tenant_id.as_ref().unwrap_or(&metadata.tenant_id);
        let rekey_edek = |edek: EdekWithKeyIdHeader| {
            let dek = Self::decrypt_document_dek(edek, &self.config.secrets, &metadata.tenant_id)?;
            let (current_secret_id, current_secret) = self.get_current_secret_and_id()?;
            let encryption_key =
                derive_aes_encryption_key(&current_secret.secret, parsed_new_tenant_id);
            let (_, v4_doc) = v5::aes::generate_aes_edek_and_sign(
                &mut *get_rng(&self.rng),
                encryption_key,
                Some(dek),
                current_secret_id.to_string().as_str(),
            )?;
            Ok(EdekWithKeyIdHeader::new(
                Self::create_key_id_header(current_secret_id),
                v4_doc,
            ))
        };
        Ok(collection_to_batch_result(edeks, rekey_edek).into())
    }

    async fn encrypt_with_existing_edek(
        &self,
        plaintext_document: PlaintextDocumentWithEdek,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let dek = Self::decrypt_document_dek(
            plaintext_document.edek.clone(),
            &self.config.secrets,
            &metadata.tenant_id,
        )?;

        let encrypted_document: HashMap<_, _> =
            encrypt_map(plaintext_document.document, self.rng.clone(), dek)?;

        Ok(EncryptedDocument {
            edek: plaintext_document.edek,
            document: encrypted_document,
        })
    }
}

/// Try to find the aes edek in the V4 header and decrypt the aes edek using the provided kek.
/// Will fail if the signature verification fails, decryption fails or if an aes edek could not be found.
fn decrypt_aes_edek(
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
        .ok_or_else(|| AlloyError::DecryptError("No AES EDEK found.".to_string()))?;
    let aes_dek = v5::aes::decrypt_aes_edek(kek, aes_edek)?;
    verify_sig(aes_dek, header)?;
    Ok(aes_dek)
}

/// Derives an encryption key for the given tenant and secret. Note that this is the same way that it's done in cloaked search for compatibility
/// with edeks from there.
fn derive_aes_encryption_key<K: AsRef<[u8]>>(
    derivation_key: &K,
    tenant_id: &TenantId,
) -> EncryptionKey {
    let resulting_bytes: String =
        Itertools::intersperse([tenant_id.0.as_str(), "encryption_key"].into_iter(), "-").collect();
    EncryptionKey(hash256(derivation_key.as_ref(), resulting_bytes))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Secret;
    use crate::{standard::EdekWithKeyIdHeader, util::create_test_seeded_rng};
    use ironcore_documents::v5::key_id_header::{self, EdekType, KeyId, PayloadType};

    fn default_client() -> StandaloneStandardClient {
        new_client(Some(1))
    }

    fn new_client(primary_secret_id: Option<u32>) -> StandaloneStandardClient {
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
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let encrypted = client.encrypt(document.clone(), &metadata).await.unwrap();
        let (key_id_header, _) =
            key_id_header::decode_version_prefixed_value(encrypted.edek.0.clone().into()).unwrap();
        assert_eq!(key_id_header.key_id, KeyId(1));
        assert_eq!(key_id_header.edek_type, EdekType::Standalone);
        assert_eq!(key_id_header.payload_type, PayloadType::StandardEdek);
        let decrypted = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(decrypted, document);
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_with_existing_edek_roundtrip() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let document2: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 4])].into();
        let encrypted = client.encrypt(document.clone(), &metadata).await.unwrap();
        let encrypted_2 = client
            .encrypt_with_existing_edek(
                PlaintextDocumentWithEdek::new(encrypted.edek.clone(), document2.clone()),
                &metadata,
            )
            .await
            .unwrap();
        let decrypted = client
            .decrypt(encrypted_2.clone(), &metadata)
            .await
            .unwrap();
        assert_eq!(encrypted.edek, encrypted_2.edek);
        assert_eq!(decrypted, document2);
        Ok(())
    }

    #[tokio::test]
    async fn rekey_edek_roundtrip() {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let encrypted = client.encrypt(document.clone(), &metadata).await.unwrap();
        let mut rekeyed = client
            .rekey_edeks(
                [("foo".to_string(), encrypted.edek.clone())].into(),
                &metadata,
                None,
            )
            .await
            .unwrap();
        assert!(rekeyed.failures.is_empty());
        assert!(rekeyed.successes.contains_key("foo"));
        let new_edek = rekeyed.successes.remove("foo").unwrap();
        assert_ne!(encrypted.edek, new_edek);
        let remade_document = EncryptedDocument {
            edek: new_edek,
            document: encrypted.document,
        };
        let decrypted = client.decrypt(remade_document, &metadata).await.unwrap();
        assert_eq!(decrypted, document);
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
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let encrypted = client.encrypt(document.clone(), &metadata).await.unwrap();
        let new_client = new_client(Some(2));
        let mut rekeyed = new_client
            .rekey_edeks(
                [("foo".to_string(), encrypted.edek.clone())].into(),
                &metadata,
                None,
            )
            .await
            .unwrap();
        assert!(rekeyed.failures.is_empty());
        assert!(rekeyed.successes.contains_key("foo"));
        let new_edek = rekeyed.successes.remove("foo").unwrap();
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
        assert_eq!(decrypted, document);
    }

    #[tokio::test]
    async fn decrypt_missing_key_from_config() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let encrypted = EncryptedDocument {
            //The header having a `4` means that the edek is for key id 4.
            edek: EdekWithKeyIdHeader(vec![0, 0, 0, 4, 130, 0]),
            document: HashMap::new(),
        };
        let error = client.decrypt(encrypted, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration(
                "Provided secret id `4` does not exist in the standard configuration.".to_string()
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_missing_primary() -> Result<(), AlloyError> {
        let client = new_client(None);
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let error = client.encrypt(document, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration(
                "No primary secret exists in the standard configuration".to_string()
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_primary_not_found() -> Result<(), AlloyError> {
        // This id isn't in the config map.
        let client = new_client(Some(1000));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let error = client.encrypt(document, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidConfiguration(
                "Primary secret id not found in secrets map".to_string()
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_id_not_primary() -> Result<(), AlloyError> {
        //The edek below is for key_id 1, setting primary to 2 in the sdk to 2.
        let client = new_client(Some(2));
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into();
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![
                0, 0, 0, 1, 130, 0, 10, 36, 10, 32, 63, 209, 198, 171, 21, 208, 189, 114, 147, 46,
                77, 51, 5, 205, 148, 219, 103, 230, 206, 111, 139, 227, 209, 247, 100, 74, 55, 178,
                42, 107, 148, 237, 16, 1, 18, 71, 18, 69, 26, 67, 10, 12, 248, 21, 21, 9, 41, 0,
                71, 124, 244, 209, 252, 151, 18, 48, 77, 53, 19, 139, 40, 178, 7, 81, 160, 95, 18,
                209, 6, 53, 112, 39, 222, 52, 235, 151, 227, 69, 139, 208, 207, 8, 32, 92, 4, 28,
                59, 126, 89, 87, 96, 177, 145, 45, 167, 75, 142, 49, 14, 249, 71, 29, 207, 70, 26,
                1, 49,
            ]),
            document: [(
                "hi".to_string(),
                vec![
                    0, 73, 82, 79, 78, 7, 10, 168, 250, 84, 170, 243, 140, 53, 47, 99, 212, 184,
                    119, 142, 12, 136, 196, 155, 120, 225, 188, 254, 66, 143, 227, 183, 50, 78, 0,
                    50,
                ],
            )]
            .into(),
        };
        let plaintext = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(plaintext, document);
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_edek_type_not_match() -> Result<(), AlloyError> {
        let client = default_client();
        let metadata = AlloyMetadata::new_simple(TenantId("foo".to_string()));
        let encrypted = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![0, 0, 0, 1, 0, 0]),
            document: HashMap::new(),
        };
        let error = client.decrypt(encrypted, &metadata).await.unwrap_err();
        assert_eq!(
            error,
            AlloyError::InvalidInput(
                "The data indicated that this was not a Standalone Standard EDEK wrapped value. Found: SaaS Shield, Deterministic Field"
                    .to_string()
            )
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
