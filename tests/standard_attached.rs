mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{TestResult, get_client};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ironcore_alloy::standard_attached::{
        EncryptedAttachedDocument, EncryptedAttachedDocuments, PlaintextAttachedDocuments,
        StandardAttachedDocumentOps,
    };
    use ironcore_alloy::{
        AlloyMetadata, DocumentId, TenantId,
        errors::AlloyError,
        saas_shield::{DataEvent, SaasShieldSecurityEventOps, SecurityEvent},
        standard_attached::PlaintextAttachedDocument,
    };
    use ironcore_alloy::{EncryptedBytes, PlaintextBytes};
    use rstest::rstest;
    use serde_json::{Map, Value};
    use std::sync::Arc;

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextAttachedDocument {
        PlaintextAttachedDocument(PlaintextBytes(vec![1, 2, 3]))
    }

    fn get_ciphertext() -> EncryptedAttachedDocument {
        EncryptedAttachedDocument(EncryptedBytes(vec![
            0, 0, 1, 255, 2, 0, 0, 253, 10, 36, 10, 32, 37, 182, 28, 151, 163, 201, 148, 166, 38,
            98, 139, 235, 173, 240, 18, 97, 90, 158, 165, 68, 239, 128, 213, 252, 29, 223, 194,
            125, 34, 51, 106, 186, 16, 1, 18, 212, 1, 18, 209, 1, 18, 206, 1, 10, 48, 11, 203, 103,
            246, 234, 139, 239, 124, 163, 186, 37, 0, 184, 36, 148, 241, 95, 151, 67, 120, 239,
            208, 228, 241, 141, 122, 108, 185, 52, 63, 173, 170, 25, 147, 7, 219, 239, 234, 59,
            229, 149, 63, 222, 209, 133, 25, 57, 58, 16, 255, 3, 24, 132, 5, 34, 12, 221, 39, 233,
            134, 113, 214, 84, 242, 3, 44, 10, 240, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165, 4,
            100, 135, 111, 66, 226, 238, 234, 187, 39, 1, 190, 73, 104, 43, 97, 48, 24, 182, 199,
            114, 240, 85, 11, 252, 38, 197, 137, 135, 190, 229, 100, 194, 174, 18, 73, 0, 220, 248,
            78, 140, 15, 105, 117, 69, 235, 192, 187, 136, 27, 151, 154, 173, 63, 79, 132, 234,
            158, 124, 80, 147, 68, 24, 43, 139, 72, 97, 113, 87, 12, 209, 112, 245, 218, 151, 132,
            194, 69, 217, 12, 210, 242, 186, 147, 85, 71, 86, 148, 77, 113, 106, 21, 39, 12, 145,
            161, 187, 194, 33, 33, 203, 101, 51, 206, 14, 223, 250, 95, 222, 16, 255, 3, 50, 12,
            116, 101, 110, 97, 110, 116, 45, 103, 99, 112, 45, 108, 87, 49, 227, 3, 137, 101, 136,
            209, 137, 109, 39, 207, 43, 133, 71, 96, 232, 250, 31, 212, 138, 200, 51, 23, 213, 139,
            96, 36, 111, 153, 33,
        ]))
    }

    fn get_v4_ciphertext() -> EncryptedAttachedDocument {
        let decoded = STANDARD.decode("BElST04A/QokCiBvYPHzvTW/gGnRJVMIUrFeZc/mcZjTXpU0KaltEM3/fRABEtQBEtEBEs4BCjDJDBYx+NdrCP3vsy05hBHDLP6IXeboCH+sYya/1ycUZlNmFKgkpAjIcBjnovfEunIQ/wMYhAUiDAcq7Se4Ea3H/pcEaCp4CnYKcQokAKUEZIdvQuLu6rsnAb5JaCthMBi2x3LwVQv8JsWJh77lZMKuEkkA3PhOjA9pdUXrwLuIG5earT9PhOqefFCTRBgri0hhcVcM0XD12peEwkXZDNLyupNVR1aUTXFqFScMkaG7wiEhy2Uzzg7f+l/eEP8DMgx0ZW5hbnQtZ2NwLWxUnq+7pZ5UJFqlbQiAD4p1uechLz1hlLhGgEPDV9OTi3eMAvvAeNJedYDang==").unwrap();
        EncryptedAttachedDocument(EncryptedBytes(decoded))
    }

    #[tokio::test]
    async fn standard_attached_encrypt_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .standard_attached()
            .encrypt(plaintext, &metadata)
            .await?;
        assert_eq!(encrypted.0.0.len(), 292);
        Ok(())
    }

    #[tokio::test]
    async fn standard_attached_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client()
            .standard_attached()
            .decrypt(encrypted, &metadata)
            .await?;
        let expected = get_plaintext();
        assert_eq!(decrypted, expected);
        Ok(())
    }

    #[tokio::test]
    async fn standard_attached_decrypt_v4_document() -> TestResult {
        let document = get_v4_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client()
            .standard_attached()
            .decrypt(document, &metadata)
            .await
            .unwrap();
        let expected = serde_json::json!({"title": "blah"})
            .as_object()
            .unwrap()
            .clone();
        let decrypted_json = serde_json::from_slice::<Map<String, Value>>(&decrypted.0.0).unwrap();
        assert_eq!(expected, decrypted_json);
        Ok(())
    }

    #[tokio::test]
    async fn standard_attached_batch_roundtrip() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let documents: PlaintextAttachedDocuments =
            PlaintextAttachedDocuments([(DocumentId("doc".to_string()), plaintext)].into());
        let encrypted = get_client()
            .standard_attached()
            .encrypt_batch(documents, &metadata)
            .await?;
        assert_eq!(encrypted.successes.0.len(), 1);
        assert_eq!(encrypted.failures.len(), 0);
        let bad_document =
            EncryptedAttachedDocument(EncryptedBytes(vec![0, 0, 1, 255, 2, 0, 0, 2, 10, 36]));
        let new_encrypted: EncryptedAttachedDocuments = EncryptedAttachedDocuments(
            encrypted
                .successes
                .0
                .into_iter()
                .chain([(DocumentId("bad_doc".to_string()), bad_document)])
                .collect(),
        );
        let decrypted = get_client()
            .standard_attached()
            .decrypt_batch(new_encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 1);
        assert_eq!(decrypted.failures.len(), 1);
        assert_eq!(
            decrypted
                .successes
                .0
                .get(&DocumentId("doc".to_string()))
                .unwrap(),
            &get_plaintext()
        );
        assert!(matches!(
            decrypted
                .failures
                .get(&DocumentId("bad_doc".to_string()))
                .unwrap(),
            AlloyError::InvalidInput { .. }
        ));
        Ok(())
    }

    #[rstest]
    #[case::with_timestamp(Some(1000), true)]
    #[case::without_timestamp(None, true)]
    #[case::negative_timestamp(Some(-1), false)]
    #[tokio::test]
    async fn standard_attached_log_security_event(
        #[case] event_time: Option<i64>,
        #[case] expect_success: bool,
    ) -> TestResult {
        let result = get_client()
            .standard_attached()
            .log_security_event(
                SecurityEvent::Data {
                    event: DataEvent::ChangePermissions,
                },
                &get_metadata(),
                event_time,
            )
            .await;
        if expect_success {
            result?;
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "Invalid input: 'millis times must be >= 0.'"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn standard_attached_get_searchable_edek_prefix_works() -> TestResult {
        let prefix = get_client()
            .standard_attached()
            .get_searchable_edek_prefix(1);
        let expected = [0, 0, 0, 1, 2, 0];
        assert_eq!(prefix, expected);
        Ok(())
    }

    #[rstest]
    #[case::same_tenant(None, &[0, 0, 1, 255, 2, 0])]
    #[case::new_tenant(Some("tenant-aws"), &[0, 0, 2, 0, 2, 0])]
    #[tokio::test]
    async fn standard_attached_rekey(
        #[case] new_tenant_id: Option<&str>,
        #[case] expected_prefix: &[u8],
    ) -> TestResult {
        let metadata = get_metadata();
        let doc = get_ciphertext();
        let docs = EncryptedAttachedDocuments([(DocumentId("doc".to_string()), doc)].into());
        let new_tenant = new_tenant_id.map(|id| TenantId(id.to_string()));
        let mut all_rekeyed = get_client()
            .standard_attached()
            .rekey_documents(docs, &metadata, new_tenant.clone())
            .await?;
        assert_eq!(all_rekeyed.successes.len(), 1);
        assert_eq!(all_rekeyed.failures.len(), 0);
        let rekeyed = all_rekeyed
            .successes
            .remove(&DocumentId("doc".to_string()))
            .unwrap();
        assert!(rekeyed.0.0.starts_with(expected_prefix));
        // When rekeyed to a new tenant, decrypting with the original metadata must fail
        if new_tenant.is_some() {
            let err = get_client()
                .standard_attached()
                .decrypt(rekeyed.clone(), &metadata)
                .await
                .unwrap_err();
            assert!(matches!(err, AlloyError::TspError { .. }));
        }
        let decrypt_metadata = match &new_tenant {
            Some(tid) => AlloyMetadata::new_simple(tid.clone()),
            None => metadata,
        };
        let decrypted = get_client()
            .standard_attached()
            .decrypt(rekeyed, &decrypt_metadata)
            .await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }
}
