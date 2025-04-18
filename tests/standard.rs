mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{TestResult, get_client};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ironcore_alloy::{
        AlloyMetadata, DocumentId, EncryptedBytes, FieldId, TenantId,
        errors::{AlloyError, KmsError, TenantSecurityProxyError},
        saas_shield::{DataEvent, SaasShieldSecurityEventOps, SecurityEvent},
        standard::{
            EdekWithKeyIdHeader, EncryptedDocument, EncryptedDocuments, PlaintextDocument,
            PlaintextDocumentWithEdek, PlaintextDocuments, PlaintextDocumentsWithEdeks,
            StandardDocumentOps,
        },
    };
    use std::{
        collections::HashMap,
        str::from_utf8,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextDocument {
        PlaintextDocument([(FieldId("field".to_string()), vec![1, 2, 3].into())].into())
    }

    fn get_ciphertext() -> EncryptedDocument {
        EncryptedDocument {
            edek: EdekWithKeyIdHeader(
                vec![
                    0, 0, 0, 0, 2, 0, 10, 36, 10, 32, 64, 210, 116, 17, 37, 169, 25, 195, 73, 47,
                    59, 120, 34, 200, 205, 142, 3, 154, 115, 130, 188, 198, 244, 161, 170, 163,
                    153, 254, 43, 237, 157, 167, 16, 1, 18, 215, 1, 18, 212, 1, 18, 209, 1, 10,
                    192, 1, 10, 48, 63, 225, 165, 108, 33, 17, 151, 119, 230, 185, 159, 203, 90,
                    67, 250, 185, 117, 54, 184, 68, 240, 128, 92, 176, 48, 35, 52, 183, 27, 153,
                    15, 247, 241, 63, 221, 179, 246, 99, 9, 98, 221, 121, 156, 193, 220, 197, 225,
                    126, 16, 255, 3, 24, 128, 5, 34, 12, 39, 49, 127, 75, 144, 142, 37, 173, 138,
                    210, 233, 129, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165, 4, 100, 135, 130, 34,
                    228, 127, 190, 188, 55, 199, 103, 184, 137, 98, 81, 5, 243, 99, 119, 248, 110,
                    101, 114, 150, 161, 28, 100, 228, 110, 64, 123, 169, 222, 18, 73, 0, 220, 248,
                    78, 140, 39, 11, 119, 244, 9, 168, 242, 190, 48, 191, 108, 152, 157, 29, 120,
                    97, 56, 118, 104, 45, 144, 16, 245, 170, 9, 52, 111, 40, 22, 174, 185, 135,
                    102, 95, 142, 171, 180, 163, 118, 46, 183, 105, 45, 137, 66, 170, 61, 49, 166,
                    47, 184, 99, 232, 86, 42, 73, 118, 87, 194, 50, 103, 109, 176, 41, 144, 121,
                    250, 182, 16, 255, 3, 50, 12, 116, 101, 110, 97, 110, 116, 45, 103, 99, 112,
                    45, 108,
                ]
                .into(),
            ),
            document: {
                [(
                    FieldId("field".to_string()),
                    vec![
                        0, 73, 82, 79, 78, 17, 141, 140, 32, 16, 123, 34, 245, 254, 78, 229, 190,
                        61, 60, 110, 130, 220, 41, 146, 203, 134, 189, 195, 41, 179, 146, 123, 33,
                        237, 147, 247,
                    ]
                    .into(),
                )]
                .into()
            },
        }
    }

    fn get_v3_ciphertext() -> EncryptedDocument {
        let edek = "CsABCjCkFe10OS/aiG6p9I0ijOirFq1nsRE8cPMog/bhOS0vYv5OCrYGZMSxOlo6dMJEYNgQ/wMYgAUiDEzjRFRtGVz1SRGWoip4CnYKcQokAKUEZIeCIuR/vrw3x2e4iWJRBfNjd/huZXKWoRxk5G5Ae6neEkkA3PhOjCcLd/QJqPK+ML9smJ0deGE4dmgtkBD1qgk0bygWrrmHZl+Oq7Sjdi63aS2JQqo9MaYvuGPoVipJdlfCMmdtsCmQefq2EP8D";
        let edek_bytes = EncryptedBytes(STANDARD.decode(edek).unwrap());
        let doc = EncryptedBytes(vec![
            3, 73, 82, 79, 78, 0, 46, 10, 28, 101, 22, 60, 138, 170, 207, 86, 19, 19, 80, 220, 33,
            207, 60, 229, 7, 199, 67, 192, 206, 5, 184, 244, 26, 25, 152, 187, 219, 26, 14, 10, 12,
            116, 101, 110, 97, 110, 116, 45, 103, 99, 112, 45, 108, 125, 137, 60, 34, 63, 241, 194,
            170, 25, 76, 63, 201, 94, 4, 42, 96, 60, 43, 166, 21, 23, 241, 84, 167, 65, 83, 176, 7,
            98, 227, 95, 197, 56, 207, 118, 75, 48, 64, 65, 92, 96, 163, 227, 114, 108, 183, 222,
            154,
        ]);
        let doc_bytes = [(FieldId("doc".to_string()), doc)].into();
        EncryptedDocument {
            edek: EdekWithKeyIdHeader(EncryptedBytes(edek_bytes.0)),
            document: doc_bytes,
        }
    }

    #[tokio::test]
    async fn standard_encrypt_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .standard()
            .encrypt(plaintext, &metadata)
            .await?;
        assert_eq!(encrypted.edek.0.0.len(), 259);
        Ok(())
    }

    #[tokio::test]
    async fn standard_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client()
            .standard()
            .decrypt(encrypted, &metadata)
            .await?;
        let expected = get_plaintext();
        assert_eq!(decrypted, expected);
        Ok(())
    }

    #[tokio::test]
    async fn standard_decrypt_v3_document() -> TestResult {
        let document = get_v3_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client()
            .standard()
            .decrypt(document, &metadata)
            .await
            .unwrap();
        let decrypted_string =
            std::str::from_utf8(&decrypted.0.get(&FieldId("doc".to_string())).unwrap().0).unwrap();
        assert_eq!(decrypted_string, "Encrypt these bytes!");
        Ok(())
    }

    #[tokio::test]
    async fn standard_batch_roundtrip() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let documents = PlaintextDocuments([(DocumentId("doc".to_string()), plaintext)].into());
        let encrypted = get_client()
            .standard()
            .encrypt_batch(documents, &metadata)
            .await?;
        assert_eq!(encrypted.successes.0.len(), 1);
        assert_eq!(encrypted.failures.len(), 0);
        let second_document = get_v3_ciphertext();
        let bad_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![1].into()),
            document: HashMap::new(),
        };
        let new_encrypted = EncryptedDocuments(
            encrypted
                .successes
                .0
                .into_iter()
                .chain([
                    (DocumentId("v3_doc".to_string()), second_document),
                    (DocumentId("bad_doc".to_string()), bad_document),
                ])
                .collect(),
        );
        let decrypted = get_client()
            .standard()
            .decrypt_batch(new_encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert_eq!(decrypted.failures.len(), 1);
        assert_eq!(
            decrypted
                .successes
                .0
                .get(&DocumentId("doc".to_string()))
                .unwrap(),
            &get_plaintext()
        );
        let decrypted_v3 = from_utf8(
            &decrypted
                .successes
                .0
                .get(&DocumentId("v3_doc".to_string()))
                .unwrap()
                .0
                .get(&FieldId("doc".to_string()))
                .unwrap()
                .0,
        )
        .unwrap();
        assert_eq!(decrypted_v3, "Encrypt these bytes!");
        assert!(matches!(
            decrypted
                .failures
                .get(&DocumentId("bad_doc".to_string()))
                .unwrap(),
            AlloyError::DecryptError { .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn standard_encrypt_with_existing_edek_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .standard()
            .encrypt(plaintext, &metadata)
            .await?;
        let plaintext2 =
            PlaintextDocument([(FieldId("field2".to_string()), vec![1, 2, 3, 4].into())].into());
        let plaintext_with_edek = PlaintextDocumentWithEdek {
            edek: encrypted.edek.clone(),
            document: plaintext2.clone(),
        };
        let second_encrypted = get_client()
            .standard()
            .encrypt_with_existing_edek(plaintext_with_edek, &metadata)
            .await?;
        assert_eq!(&encrypted.edek, &second_encrypted.edek);
        let decrypted = get_client()
            .standard()
            .decrypt(second_encrypted, &metadata)
            .await?;
        assert_eq!(decrypted, plaintext2);
        Ok(())
    }

    #[tokio::test]
    async fn standard_encrypt_with_existing_edek_batch_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .standard()
            .encrypt(plaintext, &metadata)
            .await?;
        let plaintext2 =
            PlaintextDocument([(FieldId("field2".to_string()), vec![1, 2, 3, 4].into())].into());
        let plaintext_with_edek = PlaintextDocumentWithEdek {
            edek: encrypted.edek,
            document: plaintext2.clone(),
        };
        let plaintexts = PlaintextDocumentsWithEdeks(
            [(DocumentId("doc".to_string()), plaintext_with_edek)].into(),
        );
        let mut batch_encrypted = get_client()
            .standard()
            .encrypt_with_existing_edek_batch(plaintexts, &metadata)
            .await?;
        assert_eq!(batch_encrypted.successes.0.len(), 1);
        assert_eq!(batch_encrypted.failures.len(), 0);
        let decrypted = get_client()
            .standard()
            .decrypt(
                batch_encrypted
                    .successes
                    .0
                    .remove(&DocumentId("doc".to_string()))
                    .unwrap(),
                &metadata,
            )
            .await?;
        assert_eq!(decrypted, plaintext2);
        Ok(())
    }

    #[tokio::test]
    async fn standard_encrypt_with_existing_v3_edek_works() -> TestResult {
        let metadata = get_metadata();
        let edek = "CsABCjCkFe10OS/aiG6p9I0ijOirFq1nsRE8cPMog/bhOS0vYv5OCrYGZMSxOlo6dMJEYNgQ/wMYgAUiDEzjRFRtGVz1SRGWoip4CnYKcQokAKUEZIeCIuR/vrw3x2e4iWJRBfNjd/huZXKWoRxk5G5Ae6neEkkA3PhOjCcLd/QJqPK+ML9smJ0deGE4dmgtkBD1qgk0bygWrrmHZl+Oq7Sjdi63aS2JQqo9MaYvuGPoVipJdlfCMmdtsCmQefq2EP8D";
        let edek_bytes = STANDARD.decode(edek).unwrap();
        let plaintext =
            PlaintextDocument([(FieldId("field2".to_string()), vec![1, 2, 3, 4].into())].into());
        let plaintext_with_edek = PlaintextDocumentWithEdek {
            edek: EdekWithKeyIdHeader(edek_bytes.clone().into()),
            document: plaintext.clone(),
        };
        let encrypted = get_client()
            .standard()
            .encrypt_with_existing_edek(plaintext_with_edek, &metadata)
            .await?;
        assert_eq!(encrypted.edek.0.0, edek_bytes);
        let decrypted = get_client()
            .standard()
            .decrypt(encrypted, &metadata)
            .await?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn standard_log_security_event_works() -> TestResult {
        let metadata = get_metadata();
        get_client()
            .standard()
            .log_security_event(
                SecurityEvent::Data {
                    event: DataEvent::ChangePermissions,
                },
                &metadata,
                Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64,
                ),
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn standard_log_security_event_works_with_none() -> TestResult {
        let metadata = get_metadata();
        get_client()
            .standard()
            .log_security_event(
                SecurityEvent::Data {
                    event: DataEvent::ChangePermissions,
                },
                &metadata,
                None,
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn standard_log_security_event_fails_with_negative_time() -> TestResult {
        let metadata = get_metadata();
        let err = get_client()
            .standard()
            .log_security_event(
                SecurityEvent::Data {
                    event: DataEvent::ChangePermissions,
                },
                &metadata,
                Some(-1),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid input: 'millis times must be >= 0.'"
        );
        Ok(())
    }
    #[tokio::test]
    async fn standard_get_searchable_edek_prefix_works() -> TestResult {
        let prefix = get_client().standard().get_searchable_edek_prefix(1);
        let expected = [0, 0, 0, 1, 2, 0];
        assert_eq!(prefix, expected);
        Ok(())
    }

    #[tokio::test]
    async fn standard_rekey_v5_edek_works() -> TestResult {
        let metadata = get_metadata();
        let edek = get_ciphertext().edek;
        let edeks = [(DocumentId("edek".to_string()), edek)].into();
        let all_rekeyed = get_client()
            .standard()
            .rekey_edeks(edeks, &metadata, None)
            .await?;
        assert!(
            all_rekeyed
                .successes
                .contains_key(&DocumentId("edek".to_string()))
        );
        assert!(all_rekeyed.failures.is_empty());
        let rekeyed = all_rekeyed
            .successes
            .get(&DocumentId("edek".to_string()))
            .unwrap();
        // First 4 bytes are KMS config ID 511
        assert!(rekeyed.0.0.starts_with(&[0, 0, 1, 255, 2, 0]));
        Ok(())
    }

    #[tokio::test]
    async fn standard_rekey_v3_edek_works() -> TestResult {
        let metadata = get_metadata();
        let edek = "CsABCjCkFe10OS/aiG6p9I0ijOirFq1nsRE8cPMog/bhOS0vYv5OCrYGZMSxOlo6dMJEYNgQ/wMYgAUiDEzjRFRtGVz1SRGWoip4CnYKcQokAKUEZIeCIuR/vrw3x2e4iWJRBfNjd/huZXKWoRxk5G5Ae6neEkkA3PhOjCcLd/QJqPK+ML9smJ0deGE4dmgtkBD1qgk0bygWrrmHZl+Oq7Sjdi63aS2JQqo9MaYvuGPoVipJdlfCMmdtsCmQefq2EP8D";
        let edek_bytes = STANDARD.decode(edek).unwrap();
        let edeks = [(
            DocumentId("edek".to_string()),
            EdekWithKeyIdHeader(edek_bytes.into()),
        )]
        .into();
        let all_rekeyed = get_client()
            .standard()
            .rekey_edeks(edeks, &metadata, None)
            .await?;
        assert!(
            all_rekeyed
                .successes
                .contains_key(&DocumentId("edek".to_string()))
        );
        assert!(all_rekeyed.failures.is_empty());
        let rekeyed = all_rekeyed
            .successes
            .get(&DocumentId("edek".to_string()))
            .unwrap();
        // This is now a V5 document, which starts with the KeyIdHeader
        // First 4 bytes are KMS config ID 511
        assert!(rekeyed.0.0.starts_with(&[0, 0, 1, 255, 2, 0]));
        Ok(())
    }

    #[tokio::test]
    async fn test_error_variant() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = AlloyMetadata::new_simple(TenantId("fake-tenant".to_string()));
        let err = get_client()
            .standard()
            .decrypt(encrypted, &metadata)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AlloyError::TspError {
                error: TenantSecurityProxyError::Kms {
                    error: KmsError::UnknownTenantOrNoActiveKmsConfigurations,
                },
                ..
            }
        ));
        Ok(())
    }
}
