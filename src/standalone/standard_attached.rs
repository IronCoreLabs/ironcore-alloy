use super::{config::StandaloneConfiguration, standard::StandaloneStandardClient};
use crate::{
    AlloyMetadata, TenantId,
    errors::AlloyError,
    standard::StandardDocumentOps,
    standard_attached::{
        EncryptedAttachedDocument, EncryptedAttachedDocuments, PlaintextAttachedDocument,
        PlaintextAttachedDocuments, RekeyAttachedDocumentsBatchResult,
        StandardAttachedDecryptBatchResult, StandardAttachedDocumentOps,
        StandardAttachedEncryptBatchResult, decrypt_batch_core, decrypt_core, encrypt_batch_core,
        encrypt_core, rekey_core,
    },
};

#[derive(uniffi::Object)]
pub struct StandaloneStandardAttachedClient {
    standard_client: StandaloneStandardClient,
}

impl StandaloneStandardAttachedClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        Self {
            standard_client: StandaloneStandardClient::new(config),
        }
    }
}

#[uniffi::export]
#[async_trait::async_trait]
impl StandardAttachedDocumentOps for StandaloneStandardAttachedClient {
    /// Encrypt a document with the provided metadata.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key.
    /// The result is a single blob of bytes with the edek put on the front of it.
    async fn encrypt(
        &self,
        plaintext_document: PlaintextAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError> {
        encrypt_core(&self.standard_client, plaintext_document.0, metadata).await
    }

    /// Encrypt multiple documents with the provided metadata.
    /// A DEK (document encryption key) will be generated for each document and encrypted using a derived key.
    async fn encrypt_batch(
        &self,
        plaintext_documents: PlaintextAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedEncryptBatchResult, AlloyError> {
        encrypt_batch_core(&self.standard_client, plaintext_documents, metadata).await
    }

    /// Decrypt a document that was encrypted with the provided metadata.
    /// The document must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt(
        &self,
        encrypted_document: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextAttachedDocument, AlloyError> {
        decrypt_core(&self.standard_client, encrypted_document, metadata)
            .await
            .map(PlaintextAttachedDocument)
    }

    /// Decrypt multiple documents that were encrypted with the provided metadata.
    /// The documents must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt_batch(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedDecryptBatchResult, AlloyError> {
        decrypt_batch_core(&self.standard_client, encrypted_documents, metadata).await
    }

    /// Decrypt the provided documents and re-encrypt them using the tenant's current key. If `new_tenant_id` is `None`,
    /// the documents will be encrypted to the original tenant.
    async fn rekey_documents(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyAttachedDocumentsBatchResult, AlloyError> {
        rekey_core(
            &self.standard_client,
            encrypted_documents,
            metadata,
            new_tenant_id,
        )
        .await
    }

    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    /// Note that this will not work for matching values that don't use our key_id_header format, such as cloaked search.
    fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
        self.standard_client.get_searchable_edek_prefix(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PlaintextBytes;
    fn default_client() -> StandaloneStandardAttachedClient {
        new_client(Some(1))
    }

    fn new_client(primary_secret_id: Option<u32>) -> StandaloneStandardAttachedClient {
        StandaloneStandardAttachedClient {
            standard_client: crate::standalone::standard::test::new_client(primary_secret_id),
        }
    }
    #[tokio::test]
    async fn test_decrypt() {
        let encrypted = [
            4u8, 73, 82, 79, 78, 0, 126, 10, 36, 10, 32, 84, 143, 174, 236, 242, 232, 183, 233, 69,
            129, 0, 163, 125, 253, 127, 116, 53, 184, 154, 130, 201, 75, 19, 146, 213, 100, 120,
            115, 50, 236, 89, 102, 16, 1, 18, 86, 18, 84, 26, 82, 10, 12, 0, 14, 254, 200, 124, 87,
            73, 236, 17, 87, 145, 46, 18, 48, 118, 142, 3, 98, 188, 135, 11, 223, 75, 168, 62, 13,
            207, 208, 110, 46, 240, 192, 83, 87, 159, 80, 101, 34, 66, 65, 35, 100, 250, 50, 135,
            122, 216, 5, 70, 243, 208, 23, 153, 155, 20, 18, 202, 57, 222, 105, 3, 137, 26, 16,
            111, 116, 104, 101, 114, 95, 105, 100, 126, 116, 101, 110, 97, 110, 116, 49, 14, 23,
            31, 96, 222, 158, 83, 65, 52, 136, 25, 162, 66, 77, 191, 170, 234, 192, 231, 78, 74, 6,
            85, 54, 115, 46, 111, 1, 252, 182, 223, 126, 38, 61, 164, 58, 209, 57, 166, 48, 25,
            250, 211, 245, 38, 231, 137, 95, 30, 251, 187, 119, 163, 65, 237, 192, 85, 156, 208,
            138, 224, 103, 220, 44, 87, 219, 181, 48, 118, 73, 229, 92, 237, 17, 92, 139, 230, 238,
            48, 138, 156, 41, 120, 237, 183, 67, 151, 169, 206, 118, 48, 155, 217, 56, 161, 250,
            68, 244, 23, 216, 105, 58, 223, 219, 58, 178, 151, 156, 18, 124, 121, 34, 216, 58, 127,
            162, 112, 3, 58, 197, 180, 204, 47, 253, 129, 26, 20, 253, 91, 225, 29, 201, 13, 36,
            185, 158, 208, 195, 119, 220, 153, 65, 134, 160, 149, 51, 180, 49, 192, 203, 189, 53,
            1, 228, 119, 67, 66, 233, 247, 52, 189, 158, 247, 86, 246, 38, 20, 137, 162, 71, 129,
            117, 188, 53, 10, 171, 41, 194, 141, 244, 24, 218, 242, 77, 42, 105, 134, 106, 191,
            216, 24, 20, 97, 188, 23, 158, 160, 66, 203, 222, 5, 48, 77, 153, 95, 165, 113, 54, 51,
            249, 15, 224, 66, 173, 155, 164, 74, 188, 5, 149, 212, 33, 153, 83, 223, 97, 6, 144,
            74, 184, 77, 213, 237, 42, 227, 162, 177, 185, 117, 149, 113, 229, 242, 247, 204, 212,
            72, 51, 103, 51, 225, 48, 2, 107, 166, 20, 26, 76, 51, 254, 176, 66, 60, 196, 156, 36,
            210, 145, 83, 200, 98, 74, 254, 137, 231, 5, 226, 146, 249, 106, 131, 188, 143, 222,
            247, 108, 123, 250, 234, 54, 86, 209, 139, 32, 150, 44, 200, 132, 178, 132, 83, 148,
            71, 24, 214, 175, 45, 61, 217, 105, 68, 238, 169, 248, 140, 103, 40, 25, 69, 81, 142,
            4, 40, 77, 174, 159, 50, 8, 255, 18, 47, 125, 52, 197, 104, 139, 133, 166, 102, 12, 64,
            96, 118, 137, 232, 110, 201, 56, 174, 186, 215, 162, 183, 67, 230, 229, 10, 190, 77, 4,
            243, 60, 234, 200, 118, 135, 158, 170, 120, 253, 54, 226, 153, 138, 143, 112, 242, 21,
            246, 63, 148, 35, 13, 14, 250, 100, 65, 4, 119, 28, 149, 25, 58, 98, 3, 209, 115, 157,
            224, 4, 50, 238, 224, 130, 33, 91, 85, 17, 119, 176, 127, 226, 175, 225, 19, 201, 247,
            108, 253, 16, 120, 160, 72, 162, 102, 215, 165, 122,
        ];
        let metadata = AlloyMetadata::new_simple(crate::TenantId("tenant1".to_string()));

        let client = default_client();
        let result = client
            .decrypt(
                EncryptedAttachedDocument(encrypted.to_vec().into()),
                &metadata,
            )
            .await
            .unwrap();

        assert_eq!(result.0, PlaintextBytes(vec![100u8; 400]));
    }

    #[tokio::test]
    async fn test_decrypt_wrong_tenant() {
        let encrypted = [
            4u8, 73, 82, 79, 78, 0, 126, 10, 36, 10, 32, 84, 143, 174, 236, 242, 232, 183, 233, 69,
            129, 0, 163, 125, 253, 127, 116, 53, 184, 154, 130, 201, 75, 19, 146, 213, 100, 120,
            115, 50, 236, 89, 102, 16, 1, 18, 86, 18, 84, 26, 82, 10, 12, 0, 14, 254, 200, 124, 87,
            73, 236, 17, 87, 145, 46, 18, 48, 118, 142, 3, 98, 188, 135, 11, 223, 75, 168, 62, 13,
            207, 208, 110, 46, 240, 192, 83, 87, 159, 80, 101, 34, 66, 65, 35, 100, 250, 50, 135,
            122, 216, 5, 70, 243, 208, 23, 153, 155, 20, 18, 202, 57, 222, 105, 3, 137, 26, 16,
            111, 116, 104, 101, 114, 95, 105, 100, 126, 116, 101, 110, 97, 110, 116, 49, 14, 23,
            31, 96, 222, 158, 83, 65, 52, 136, 25, 162, 66, 77, 191, 170, 234, 192, 231, 78, 74, 6,
            85, 54, 115, 46, 111, 1, 252, 182, 223, 126, 38, 61, 164, 58, 209, 57, 166, 48, 25,
            250, 211, 245, 38, 231, 137, 95, 30, 251, 187, 119, 163, 65, 237, 192, 85, 156, 208,
            138, 224, 103, 220, 44, 87, 219, 181, 48, 118, 73, 229, 92, 237, 17, 92, 139, 230, 238,
            48, 138, 156, 41, 120, 237, 183, 67, 151, 169, 206, 118, 48, 155, 217, 56, 161, 250,
            68, 244, 23, 216, 105, 58, 223, 219, 58, 178, 151, 156, 18, 124, 121, 34, 216, 58, 127,
            162, 112, 3, 58, 197, 180, 204, 47, 253, 129, 26, 20, 253, 91, 225, 29, 201, 13, 36,
            185, 158, 208, 195, 119, 220, 153, 65, 134, 160, 149, 51, 180, 49, 192, 203, 189, 53,
            1, 228, 119, 67, 66, 233, 247, 52, 189, 158, 247, 86, 246, 38, 20, 137, 162, 71, 129,
            117, 188, 53, 10, 171, 41, 194, 141, 244, 24, 218, 242, 77, 42, 105, 134, 106, 191,
            216, 24, 20, 97, 188, 23, 158, 160, 66, 203, 222, 5, 48, 77, 153, 95, 165, 113, 54, 51,
            249, 15, 224, 66, 173, 155, 164, 74, 188, 5, 149, 212, 33, 153, 83, 223, 97, 6, 144,
            74, 184, 77, 213, 237, 42, 227, 162, 177, 185, 117, 149, 113, 229, 242, 247, 204, 212,
            72, 51, 103, 51, 225, 48, 2, 107, 166, 20, 26, 76, 51, 254, 176, 66, 60, 196, 156, 36,
            210, 145, 83, 200, 98, 74, 254, 137, 231, 5, 226, 146, 249, 106, 131, 188, 143, 222,
            247, 108, 123, 250, 234, 54, 86, 209, 139, 32, 150, 44, 200, 132, 178, 132, 83, 148,
            71, 24, 214, 175, 45, 61, 217, 105, 68, 238, 169, 248, 140, 103, 40, 25, 69, 81, 142,
            4, 40, 77, 174, 159, 50, 8, 255, 18, 47, 125, 52, 197, 104, 139, 133, 166, 102, 12, 64,
            96, 118, 137, 232, 110, 201, 56, 174, 186, 215, 162, 183, 67, 230, 229, 10, 190, 77, 4,
            243, 60, 234, 200, 118, 135, 158, 170, 120, 253, 54, 226, 153, 138, 143, 112, 242, 21,
            246, 63, 148, 35, 13, 14, 250, 100, 65, 4, 119, 28, 149, 25, 58, 98, 3, 209, 115, 157,
            224, 4, 50, 238, 224, 130, 33, 91, 85, 17, 119, 176, 127, 226, 175, 225, 19, 201, 247,
            108, 253, 16, 120, 160, 72, 162, 102, 215, 165, 122,
        ];
        let metadata = AlloyMetadata::new_simple(crate::TenantId("tenant".to_string()));

        let client = default_client();
        let err = client
            .decrypt(
                EncryptedAttachedDocument(encrypted.to_vec().into()),
                &metadata,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AlloyError::DecryptError { msg: _ }))
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let plaintext = PlaintextBytes([1u8; 10].to_vec());
        let metadata = AlloyMetadata::new_simple(crate::TenantId("tenant".to_string()));

        let client = default_client();
        let encrypted = client
            .encrypt(PlaintextAttachedDocument(plaintext.clone()), &metadata)
            .await
            .unwrap();
        let result = client.decrypt(encrypted, &metadata).await.unwrap();
        assert_eq!(result.0, plaintext);
    }
}
