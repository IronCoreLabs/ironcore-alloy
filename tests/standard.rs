use common::CLIENT;

mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use super::*;
    use ironcore_alloy::{
        errors::AlloyError,
        standard::{
            EdekWithKeyIdHeader, EncryptedDocument, PlaintextDocument, PlaintextDocumentWithEdek,
            StandardDocumentOps,
        },
        AlloyMetadata, TenantId,
    };
    use std::{collections::HashMap, sync::Arc};

    type TestResult = Result<(), AlloyError>;

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextDocument {
        [("field".to_string(), vec![1, 2, 3])].into()
    }

    fn get_ciphertext() -> EncryptedDocument {
        EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![
                0, 0, 0, 0, 2, 0, 10, 36, 10, 32, 64, 210, 116, 17, 37, 169, 25, 195, 73, 47, 59,
                120, 34, 200, 205, 142, 3, 154, 115, 130, 188, 198, 244, 161, 170, 163, 153, 254,
                43, 237, 157, 167, 16, 1, 18, 215, 1, 18, 212, 1, 18, 209, 1, 10, 192, 1, 10, 48,
                63, 225, 165, 108, 33, 17, 151, 119, 230, 185, 159, 203, 90, 67, 250, 185, 117, 54,
                184, 68, 240, 128, 92, 176, 48, 35, 52, 183, 27, 153, 15, 247, 241, 63, 221, 179,
                246, 99, 9, 98, 221, 121, 156, 193, 220, 197, 225, 126, 16, 255, 3, 24, 128, 5, 34,
                12, 39, 49, 127, 75, 144, 142, 37, 173, 138, 210, 233, 129, 42, 120, 10, 118, 10,
                113, 10, 36, 0, 165, 4, 100, 135, 130, 34, 228, 127, 190, 188, 55, 199, 103, 184,
                137, 98, 81, 5, 243, 99, 119, 248, 110, 101, 114, 150, 161, 28, 100, 228, 110, 64,
                123, 169, 222, 18, 73, 0, 220, 248, 78, 140, 39, 11, 119, 244, 9, 168, 242, 190,
                48, 191, 108, 152, 157, 29, 120, 97, 56, 118, 104, 45, 144, 16, 245, 170, 9, 52,
                111, 40, 22, 174, 185, 135, 102, 95, 142, 171, 180, 163, 118, 46, 183, 105, 45,
                137, 66, 170, 61, 49, 166, 47, 184, 99, 232, 86, 42, 73, 118, 87, 194, 50, 103,
                109, 176, 41, 144, 121, 250, 182, 16, 255, 3, 50, 12, 116, 101, 110, 97, 110, 116,
                45, 103, 99, 112, 45, 108,
            ]),
            document: {
                [(
                    "field".to_string(),
                    vec![
                        0, 73, 82, 79, 78, 17, 141, 140, 32, 16, 123, 34, 245, 254, 78, 229, 190,
                        61, 60, 110, 130, 220, 41, 146, 203, 134, 189, 195, 41, 179, 146, 123, 33,
                        237, 147, 247,
                    ],
                )]
                .into()
            },
        }
    }

    #[tokio::test]
    async fn standard_encrypt_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = CLIENT.standard().encrypt(plaintext, &metadata).await?;
        assert_eq!(encrypted.edek.0.len(), 262);
        Ok(())
    }

    #[tokio::test]
    async fn standard_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = CLIENT.standard().decrypt(encrypted, &metadata).await?;
        let expected = get_plaintext();
        assert_eq!(decrypted, expected);
        Ok(())
    }

    #[tokio::test]
    async fn standard_encrypt_with_existing_edek_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = CLIENT.standard().encrypt(plaintext, &metadata).await?;
        let plaintext2: HashMap<_, _> = [("field2".to_string(), vec![1, 2, 3, 4])].into();
        let plaintext_with_edek = PlaintextDocumentWithEdek {
            edek: encrypted.edek,
            document: plaintext2.clone(),
        };
        let second_encrypted = CLIENT
            .standard()
            .encrypt_with_existing_edek(plaintext_with_edek, &metadata)
            .await?;
        let decrypted = CLIENT
            .standard()
            .decrypt(second_encrypted, &metadata)
            .await?;
        assert_eq!(decrypted, plaintext2);
        Ok(())
    }

    #[tokio::test]
    async fn standard_get_searchable_edek_prefix_works() -> TestResult {
        let prefix = CLIENT.standard().get_searchable_edek_prefix(1);
        let expected = [0, 0, 0, 1, 2, 0];
        assert_eq!(prefix, expected);
        Ok(())
    }
}
