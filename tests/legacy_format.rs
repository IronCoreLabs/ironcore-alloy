/// Integration tests for `legacy_tsc_write_format` covering the full format matrix.
///
/// ## Format rules
///
/// | Operation                      | Format decision                                        |
/// |--------------------------------|--------------------------------------------------------|
/// | `encrypt` / `encrypt_batch`    | Configured format (`legacy_tsc_write_format`)          |
/// | `rekey_edeks`                  | Configured format (tool for intentional format change) |
/// | `encrypt_with_existing_edek`   | Matches the provided EDEK's format (ignores config)    |
/// | `decrypt` / `decrypt_batch`    | Reads all formats regardless of config                 |
/// | `get_searchable_edek_prefix`   | Always succeeds; returned prefix only matches V5 EDEKs |
mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{TestResult, get_client, get_legacy_client};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ironcore_alloy::{
        AlloyMetadata, DocumentId, EncryptedBytes, FieldId, SaasShield, TenantId,
        standard::{
            EdekWithKeyIdHeader, EncryptedDocument, EncryptedDocuments, PlaintextDocument,
            PlaintextDocumentWithEdek, PlaintextDocuments, PlaintextDocumentsWithEdeks,
            StandardDocumentOps,
        },
    };
    use rstest::rstest;
    use std::sync::Arc;

    // ---- Format enums for exhaustive parameterization ----

    #[derive(Clone, Copy, Debug)]
    enum EdekFormat {
        V3,
        V5,
    }

    #[derive(Clone, Copy, Debug)]
    enum DocFormat {
        V3,
        V5,
    }

    impl EdekFormat {
        fn sdk(&self) -> Arc<SaasShield> {
            match self {
                EdekFormat::V3 => get_legacy_client(),
                EdekFormat::V5 => get_client(),
            }
        }

        fn assert(&self, edek: &EdekWithKeyIdHeader) {
            match self {
                EdekFormat::V3 => assert_eq!(
                    edek.0.0[0],
                    0x0a,
                    "Expected V3 EDEK (protobuf field tag), got: {:?}",
                    &edek.0.0[..6.min(edek.0.0.len())]
                ),
                EdekFormat::V5 => assert_eq!(
                    edek.0.0[5],
                    0x00,
                    "Expected V5 EDEK (key_id_header padding byte), got: {:?}",
                    &edek.0.0[..6.min(edek.0.0.len())]
                ),
            }
        }

        fn fixture(&self) -> EdekWithKeyIdHeader {
            let b64 = match self {
                EdekFormat::V3 => {
                    "CsABCjBouxrw3TFZtSO6cgPOM15ewNFH8uqIU+ordPNLK/M7vS7qihZlJVJNMnEQevFeQ18Q/wMYqg0iDKj2tv0ToheETqmBeyp4CnYKcQokAKUEZIf9Qdt+hRqFMjVQKP0EHlmWMGeU6tQs0bzmrl69vWE4EkkA3PhOjPCtLSjyH9Ds02CuqKTAl6tgBxadfFeWp9JMY059IZN6Gj+qfjT2vPdtWQR0NAhFPN3Ex1FXpqX+NNTcz59jll+2c0eLEP8D"
                }
                EdekFormat::V5 => {
                    "AAAB/wIACiQKIJfIHAaZJ4f6yH8X4NYU2C/fby6qezy6JN9eMUSdZ0cAEAES1AES0QESzgEKMEwYPte4D/yruJHfEwWOu2d8LePGkZI+opR/TT5rEPZZ7siCx7n1DUWIn3Wk+Tt9wxD/AxiqDSIMLdF7xzpHWIi10+m/KngKdgpxCiQApQRkh/1B236FGoUyNVAo/QQeWZYwZ5Tq1CzRvOauXr29YTgSSQDc+E6M8K0tKPIf0OzTYK6opMCXq2AHFp18V5an0kxjTn0hk3oaP6p+NPa8921ZBHQ0CEU83cTHUVempf401NzPn2OWX7ZzR4sQ/wMyDHRlbmFudC1nY3AtbA=="
                }
            };
            EdekWithKeyIdHeader(EncryptedBytes(STANDARD.decode(b64).unwrap()))
        }

        fn doc_format(&self) -> DocFormat {
            match self {
                EdekFormat::V3 => DocFormat::V3,
                EdekFormat::V5 => DocFormat::V5,
            }
        }
    }

    impl DocFormat {
        fn assert(&self, doc: &EncryptedDocument) {
            match self {
                DocFormat::V3 => {
                    EdekFormat::V3.assert(&doc.edek);
                    for (field_id, bytes) in &doc.document {
                        assert_eq!(
                            &bytes.0[..5],
                            &[3, 73, 82, 79, 78],
                            "Expected V3 field for {field_id:?}"
                        );
                    }
                }
                DocFormat::V5 => {
                    EdekFormat::V5.assert(&doc.edek);
                    for (field_id, bytes) in &doc.document {
                        assert_eq!(
                            &bytes.0[..5],
                            &[0, 73, 82, 79, 78],
                            "Expected V5 field for {field_id:?}"
                        );
                    }
                }
            }
        }

        fn fixture(&self) -> EncryptedBytes {
            let b64 = match self {
                DocFormat::V3 => {
                    "A0lST04ALgoc0x0jEo+VjaJpWEgrC2u//30unDURXl37Y2UbYBoOCgx0ZW5hbnQtZ2NwLWyzvlmZt+wuFmRVkkCBONrqkr9kAC/iRF+Mp8i5uRyj"
                }
                DocFormat::V5 => "AElST06Qf+HhVfgF4N7XlLUlAoOsK2Df63AkjJIkkWi9GIF7",
            };
            EncryptedBytes(STANDARD.decode(b64).unwrap())
        }
    }

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextDocument {
        PlaintextDocument([(FieldId("field".to_string()), vec![1, 2, 3].into())].into())
    }

    fn get_plaintext_docs(n: usize) -> PlaintextDocuments {
        PlaintextDocuments(
            (0..n)
                .map(|i| (DocumentId(format!("doc{i}")), get_plaintext()))
                .collect(),
        )
    }

    fn encrypted_fixture(edek: EdekFormat) -> EncryptedDocument {
        let doc = edek.doc_format();
        EncryptedDocument {
            edek: edek.fixture(),
            document: [(FieldId("field".to_string()), doc.fixture())].into(),
        }
    }

    // ---- encrypt: configured format determines output ----

    #[rstest]
    #[tokio::test]
    async fn encrypt_produces_configured_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] format: EdekFormat,
    ) -> TestResult {
        let encrypted = format
            .sdk()
            .standard()
            .encrypt(get_plaintext(), &get_metadata())
            .await?;
        format.doc_format().assert(&encrypted);
        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn encrypt_batch_produces_configured_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] format: EdekFormat,
    ) -> TestResult {
        let batch = format
            .sdk()
            .standard()
            .encrypt_batch(get_plaintext_docs(2), &get_metadata())
            .await?;
        assert!(batch.failures.is_empty());
        for doc in batch.successes.0.values() {
            format.doc_format().assert(doc);
        }
        Ok(())
    }

    // ---- decrypt: all format combos succeed ----

    #[rstest]
    #[tokio::test]
    async fn decrypt_reads_any_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] source: EdekFormat,
        #[values(EdekFormat::V3, EdekFormat::V5)] client: EdekFormat,
    ) -> TestResult {
        let decrypted = client
            .sdk()
            .standard()
            .decrypt(encrypted_fixture(source), &get_metadata())
            .await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn decrypt_batch_reads_any_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] source: EdekFormat,
        #[values(EdekFormat::V3, EdekFormat::V5)] client: EdekFormat,
    ) -> TestResult {
        let batch = client
            .sdk()
            .standard()
            .decrypt_batch(
                EncryptedDocuments(
                    [(DocumentId("doc0".to_string()), encrypted_fixture(source))].into(),
                ),
                &get_metadata(),
            )
            .await?;
        assert_eq!(batch.successes.0.len(), 1);
        assert!(batch.failures.is_empty());
        Ok(())
    }

    // ---- encrypt_with_existing_edek: output matches EDEK format ----

    #[rstest]
    #[tokio::test]
    async fn existing_edek_matches_edek_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] edek_from: EdekFormat,
        #[values(EdekFormat::V3, EdekFormat::V5)] reencrypt_with: EdekFormat,
    ) -> TestResult {
        let edek = edek_from.fixture();
        let reencrypted = reencrypt_with
            .sdk()
            .standard()
            .encrypt_with_existing_edek(
                PlaintextDocumentWithEdek::new(edek, get_plaintext()),
                &get_metadata(),
            )
            .await?;
        edek_from.doc_format().assert(&reencrypted);
        // Verify decryptable
        let decrypted = reencrypt_with
            .sdk()
            .standard()
            .decrypt(reencrypted, &get_metadata())
            .await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn existing_edek_batch_matches_edek_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] edek_from: EdekFormat,
        #[values(EdekFormat::V3, EdekFormat::V5)] reencrypt_with: EdekFormat,
    ) -> TestResult {
        let batch = reencrypt_with
            .sdk()
            .standard()
            .encrypt_with_existing_edek_batch(
                PlaintextDocumentsWithEdeks(
                    [(
                        DocumentId("doc0".to_string()),
                        PlaintextDocumentWithEdek::new(edek_from.fixture(), get_plaintext()),
                    )]
                    .into(),
                ),
                &get_metadata(),
            )
            .await?;
        assert!(batch.failures.is_empty());
        for doc in batch.successes.0.values() {
            edek_from.doc_format().assert(doc);
        }
        Ok(())
    }

    // ---- rekey_edeks: writes configured format ----

    #[rstest]
    #[tokio::test]
    async fn rekey_writes_configured_format(
        #[values(EdekFormat::V3, EdekFormat::V5)] edek_from: EdekFormat,
        #[values(EdekFormat::V3, EdekFormat::V5)] rekey_with: EdekFormat,
    ) -> TestResult {
        let edeks = [(DocumentId("doc".to_string()), edek_from.fixture())].into();
        let rekeyed = rekey_with
            .sdk()
            .standard()
            .rekey_edeks(edeks, &get_metadata(), None)
            .await?;
        assert!(rekeyed.failures.is_empty());
        rekey_with.assert(
            rekeyed
                .successes
                .get(&DocumentId("doc".to_string()))
                .unwrap(),
        );
        Ok(())
    }

    // ---- get_searchable_edek_prefix: always succeeds ----

    #[rstest]
    #[tokio::test]
    async fn prefix_always_returns_v5_bytes(
        #[values(EdekFormat::V3, EdekFormat::V5)] client_format: EdekFormat,
    ) -> TestResult {
        let prefix = client_format.sdk().standard().get_searchable_edek_prefix(1);
        assert_eq!(prefix, vec![0, 0, 0, 1, 2, 0]);
        Ok(())
    }
}
