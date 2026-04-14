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
///
/// ## Test matrix
///
/// ### encrypt / encrypt_batch (new documents)
/// - [x] legacy client → V3 EDEK + V3 fields
/// - [x] v5 client     → V5 EDEK + V5 fields
///
/// ### decrypt / decrypt_batch (cross-format reading)
/// - [x] legacy client reads V3 document
/// - [x] legacy client reads V5 document
/// - [x] v5 client reads V3 document
/// - [x] v5 client reads V5 document
///
/// ### encrypt_with_existing_edek / _batch (field format matches EDEK)
/// - [x] v5 client + V3 EDEK → V3 fields (matches EDEK, ignores config)
/// - [x] v5 client + V5 EDEK → V5 fields
/// - [x] legacy client + V3 EDEK → V3 fields
/// - [x] legacy client + V5 EDEK → V5 fields (matches EDEK, ignores config)
///
/// ### rekey_edeks (writes configured format)
/// - [x] v5 client + V3 EDEK → V5 EDEK (upgrade)
/// - [x] v5 client + V5 EDEK → V5 EDEK
/// - [x] legacy client + V3 EDEK → V3 EDEK
/// - [x] legacy client + V5 EDEK → V3 EDEK (downgrade)
///
/// ### get_searchable_edek_prefix
/// - [x] v5 client → returns V5 prefix bytes
/// - [x] legacy client → returns same V5 prefix bytes
mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{TestResult, get_client, get_legacy_client};
    use ironcore_alloy::{
        AlloyMetadata, DocumentId, FieldId, SaasShield, TenantId,
        standard::{
            EdekWithKeyIdHeader, EncryptedDocument, EncryptedDocuments, PlaintextDocument,
            PlaintextDocumentWithEdek, PlaintextDocuments, PlaintextDocumentsWithEdeks,
            StandardDocumentOps,
        },
    };
    use std::{collections::HashMap, sync::Arc};

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

    fn assert_v5_edek(edek: &EdekWithKeyIdHeader) {
        assert_eq!(
            edek.0 .0[5], 0x00,
            "Expected V5 EDEK (key_id_header padding byte), got: {:?}",
            &edek.0 .0[..6.min(edek.0 .0.len())]
        );
    }

    fn assert_v3_edek(edek: &EdekWithKeyIdHeader) {
        assert_eq!(
            edek.0 .0[0], 0x0a,
            "Expected V3 EDEK (protobuf field tag), got: {:?}",
            &edek.0 .0[..6.min(edek.0 .0.len())]
        );
    }

    fn assert_v5_fields(doc: &EncryptedDocument) {
        for (field_id, bytes) in &doc.document {
            assert_eq!(
                &bytes.0[..5],
                &[0, 73, 82, 79, 78],
                "Expected V5 field format for {field_id:?}"
            );
        }
    }

    fn assert_v3_fields(doc: &EncryptedDocument) {
        for (field_id, bytes) in &doc.document {
            assert_eq!(
                &bytes.0[..5],
                &[3, 73, 82, 79, 78],
                "Expected V3 field format for {field_id:?}"
            );
        }
    }

    fn assert_v5_document(doc: &EncryptedDocument) {
        assert_v5_edek(&doc.edek);
        assert_v5_fields(doc);
    }

    fn assert_v3_document(doc: &EncryptedDocument) {
        assert_v3_edek(&doc.edek);
        assert_v3_fields(doc);
    }

    /// Encrypt a batch with the given client and assert all docs match the expected format.
    async fn encrypt_batch_and_assert(
        client: &SaasShield,
        assert_doc: fn(&EncryptedDocument),
    ) -> Result<EncryptedDocuments, ironcore_alloy::errors::AlloyError> {
        let batch = client
            .standard()
            .encrypt_batch(get_plaintext_docs(2), &get_metadata())
            .await?;
        assert_eq!(batch.successes.0.len(), 2);
        assert!(batch.failures.is_empty());
        for doc in batch.successes.0.values() {
            assert_doc(doc);
        }
        Ok(batch.successes)
    }

    // ---- encrypt / encrypt_batch ----

    #[tokio::test]
    async fn encrypt_legacy_produces_v3() -> TestResult {
        let client = get_legacy_client();
        let encrypted = client
            .standard()
            .encrypt(get_plaintext(), &get_metadata())
            .await?;
        assert_v3_document(&encrypted);
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_batch_legacy_produces_v3() -> TestResult {
        encrypt_batch_and_assert(&get_legacy_client(), assert_v3_document).await?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_v5_produces_v5() -> TestResult {
        let client = get_client();
        let encrypted = client
            .standard()
            .encrypt(get_plaintext(), &get_metadata())
            .await?;
        assert_v5_document(&encrypted);
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_batch_v5_produces_v5() -> TestResult {
        encrypt_batch_and_assert(&get_client(), assert_v5_document).await?;
        Ok(())
    }

    // ---- decrypt / decrypt_batch (cross-format) ----

    #[tokio::test]
    async fn legacy_client_reads_v3_document() -> TestResult {
        let legacy = get_legacy_client();
        let metadata = get_metadata();
        let encrypted = legacy
            .standard()
            .encrypt(get_plaintext(), &metadata)
            .await?;
        let decrypted = legacy.standard().decrypt(encrypted, &metadata).await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[tokio::test]
    async fn legacy_client_reads_v3_document_batch() -> TestResult {
        let legacy = get_legacy_client();
        let metadata = get_metadata();
        let encrypted = encrypt_batch_and_assert(&legacy, assert_v3_document).await?;
        let decrypted = legacy
            .standard()
            .decrypt_batch(encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert!(decrypted.failures.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn legacy_client_reads_v5_document() -> TestResult {
        let v5 = get_client();
        let legacy = get_legacy_client();
        let metadata = get_metadata();
        let encrypted = v5.standard().encrypt(get_plaintext(), &metadata).await?;
        let decrypted = legacy.standard().decrypt(encrypted, &metadata).await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[tokio::test]
    async fn legacy_client_reads_v5_document_batch() -> TestResult {
        let v5 = get_client();
        let legacy = get_legacy_client();
        let metadata = get_metadata();
        let encrypted = encrypt_batch_and_assert(&v5, assert_v5_document).await?;
        let decrypted = legacy
            .standard()
            .decrypt_batch(encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert!(decrypted.failures.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn v5_client_reads_v3_document() -> TestResult {
        let legacy = get_legacy_client();
        let v5 = get_client();
        let metadata = get_metadata();
        let encrypted = legacy
            .standard()
            .encrypt(get_plaintext(), &metadata)
            .await?;
        let decrypted = v5.standard().decrypt(encrypted, &metadata).await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[tokio::test]
    async fn v5_client_reads_v3_document_batch() -> TestResult {
        let legacy = get_legacy_client();
        let v5 = get_client();
        let metadata = get_metadata();
        let encrypted = encrypt_batch_and_assert(&legacy, assert_v3_document).await?;
        let decrypted = v5
            .standard()
            .decrypt_batch(encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert!(decrypted.failures.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn v5_client_reads_v5_document() -> TestResult {
        let v5 = get_client();
        let metadata = get_metadata();
        let encrypted = v5.standard().encrypt(get_plaintext(), &metadata).await?;
        let decrypted = v5.standard().decrypt(encrypted, &metadata).await?;
        assert_eq!(decrypted, get_plaintext());
        Ok(())
    }

    #[tokio::test]
    async fn v5_client_reads_v5_document_batch() -> TestResult {
        let v5 = get_client();
        let metadata = get_metadata();
        let encrypted = encrypt_batch_and_assert(&v5, assert_v5_document).await?;
        let decrypted = v5
            .standard()
            .decrypt_batch(encrypted, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert!(decrypted.failures.is_empty());
        Ok(())
    }

    // ---- encrypt_with_existing_edek / _batch (matches EDEK format) ----

    async fn encrypt_with_existing_edek_test(
        encrypting_client: &SaasShield,
        reencrypting_client: &SaasShield,
        assert_doc: fn(&EncryptedDocument),
    ) -> TestResult {
        let metadata = get_metadata();
        // Single
        let encrypted = encrypting_client
            .standard()
            .encrypt(get_plaintext(), &metadata)
            .await?;
        let reencrypted = reencrypting_client
            .standard()
            .encrypt_with_existing_edek(
                PlaintextDocumentWithEdek::new(encrypted.edek, get_plaintext()),
                &metadata,
            )
            .await?;
        assert_doc(&reencrypted);
        // Verify decryptable
        let decrypted = reencrypting_client
            .standard()
            .decrypt(reencrypted, &metadata)
            .await?;
        assert_eq!(decrypted, get_plaintext());
        // Batch
        let batch_encrypted = encrypting_client
            .standard()
            .encrypt_batch(get_plaintext_docs(2), &metadata)
            .await?;
        let plaintext_with_edeks = PlaintextDocumentsWithEdeks(
            batch_encrypted
                .successes
                .0
                .into_iter()
                .map(|(id, doc)| {
                    (
                        id,
                        PlaintextDocumentWithEdek::new(doc.edek, get_plaintext()),
                    )
                })
                .collect(),
        );
        let batch_reencrypted = reencrypting_client
            .standard()
            .encrypt_with_existing_edek_batch(plaintext_with_edeks, &metadata)
            .await?;
        assert_eq!(batch_reencrypted.successes.0.len(), 2);
        assert!(batch_reencrypted.failures.is_empty());
        for doc in batch_reencrypted.successes.0.values() {
            assert_doc(doc);
        }
        Ok(())
    }

    #[tokio::test]
    async fn existing_edek_v5_client_v3_edek_produces_v3() -> TestResult {
        encrypt_with_existing_edek_test(&get_legacy_client(), &get_client(), assert_v3_document)
            .await
    }

    #[tokio::test]
    async fn existing_edek_v5_client_v5_edek_produces_v5() -> TestResult {
        encrypt_with_existing_edek_test(&get_client(), &get_client(), assert_v5_document).await
    }

    #[tokio::test]
    async fn existing_edek_legacy_client_v3_edek_produces_v3() -> TestResult {
        encrypt_with_existing_edek_test(
            &get_legacy_client(),
            &get_legacy_client(),
            assert_v3_document,
        )
        .await
    }

    #[tokio::test]
    async fn existing_edek_legacy_client_v5_edek_produces_v5() -> TestResult {
        encrypt_with_existing_edek_test(&get_client(), &get_legacy_client(), assert_v5_document)
            .await
    }

    // ---- rekey_edeks (writes configured format) ----

    async fn rekey_test(
        encrypting_client: &SaasShield,
        rekeying_client: &SaasShield,
        assert_edek: fn(&EdekWithKeyIdHeader),
    ) -> TestResult {
        let metadata = get_metadata();
        let encrypted = encrypting_client
            .standard()
            .encrypt(get_plaintext(), &metadata)
            .await?;
        let edeks: HashMap<_, _> =
            [(DocumentId("doc".to_string()), encrypted.edek)].into();
        let rekeyed = rekeying_client
            .standard()
            .rekey_edeks(edeks, &metadata, None)
            .await?;
        assert_eq!(rekeyed.successes.len(), 1);
        assert!(rekeyed.failures.is_empty());
        assert_edek(
            rekeyed
                .successes
                .get(&DocumentId("doc".to_string()))
                .unwrap(),
        );
        Ok(())
    }

    #[tokio::test]
    async fn rekey_v5_client_v3_edek_upgrades_to_v5() -> TestResult {
        rekey_test(&get_legacy_client(), &get_client(), assert_v5_edek).await
    }

    #[tokio::test]
    async fn rekey_v5_client_v5_edek_stays_v5() -> TestResult {
        rekey_test(&get_client(), &get_client(), assert_v5_edek).await
    }

    #[tokio::test]
    async fn rekey_legacy_client_v3_edek_stays_v3() -> TestResult {
        rekey_test(&get_legacy_client(), &get_legacy_client(), assert_v3_edek).await
    }

    #[tokio::test]
    async fn rekey_legacy_client_v5_edek_downgrades_to_v3() -> TestResult {
        rekey_test(&get_client(), &get_legacy_client(), assert_v3_edek).await
    }

    // ---- get_searchable_edek_prefix ----

    #[tokio::test]
    async fn prefix_v5_client_returns_v5_prefix() -> TestResult {
        let prefix = get_client().standard().get_searchable_edek_prefix(1);
        assert_eq!(prefix, vec![0, 0, 0, 1, 2, 0]);
        Ok(())
    }

    #[tokio::test]
    async fn prefix_legacy_client_returns_same_v5_prefix() -> TestResult {
        let prefix = get_legacy_client()
            .standard()
            .get_searchable_edek_prefix(1);
        assert_eq!(prefix, vec![0, 0, 0, 1, 2, 0]);
        Ok(())
    }
}
