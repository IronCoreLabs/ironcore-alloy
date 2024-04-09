mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{get_client, TestResult};
    use ironcore_alloy::{
        deterministic::{
            DeterministicFieldOps, EncryptedField, EncryptedFields, PlaintextField, PlaintextFields,
        },
        errors::AlloyError,
        AlloyMetadata, DerivationPath, EncryptedBytes, FieldId, SecretPath, TenantId,
    };
    use std::{iter, sync::Arc};

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextField {
        PlaintextField {
            plaintext_field: vec![1, 2, 3].into(),
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
        }
    }

    fn get_ciphertext() -> EncryptedField {
        EncryptedField {
            encrypted_field: EncryptedBytes(vec![
                0, 0, 19, 254, 0, 0, 239, 4, 228, 214, 163, 141, 230, 11, 246, 120, 121, 38, 1,
                247, 206, 60, 35, 34, 195,
            ]),
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
        }
    }

    #[tokio::test]
    async fn deterministic_encrypt_known() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .deterministic()
            .encrypt(plaintext, &metadata)
            .await?;
        let expected = get_ciphertext().encrypted_field;
        assert_eq!(encrypted.encrypted_field, expected);
        assert_eq!(encrypted.secret_path.0, "secret");
        assert_eq!(encrypted.derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client()
            .deterministic()
            .decrypt(encrypted, &metadata)
            .await?;
        let expected = get_plaintext().plaintext_field;
        assert_eq!(decrypted.plaintext_field, expected);
        assert_eq!(decrypted.secret_path.0, "secret");
        assert_eq!(decrypted.derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_batch_roundtrip() -> TestResult {
        let plaintext = get_plaintext();
        let plaintext_2 = PlaintextField {
            plaintext_field: vec![1, 2, 3].into(),
            secret_path: SecretPath("bad_path".to_string()),
            derivation_path: DerivationPath("bad_path".to_string()),
        };
        let metadata = get_metadata();
        let fields = PlaintextFields(
            [
                (FieldId("field".to_string()), plaintext),
                (FieldId("field_2".to_string()), plaintext_2),
            ]
            .into(),
        );
        let encrypted = get_client()
            .deterministic()
            .encrypt_batch(fields, &metadata)
            .await?;
        assert_eq!(encrypted.successes.len(), 2);
        assert_eq!(encrypted.failures.len(), 0);
        let bad_encrypted = EncryptedField {
            encrypted_field: vec![1, 1, 1].into(),
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
        };
        let encrypted_fields = EncryptedFields(
            iter::once(("bad_doc".to_string(), bad_encrypted))
                .chain(encrypted.successes.into_iter().map(|(k, v)| (k.0, v)))
                .collect(),
        );
        let decrypted = get_client()
            .deterministic()
            .decrypt_batch(encrypted_fields, &metadata)
            .await?;
        assert_eq!(decrypted.successes.len(), 2);
        assert_eq!(decrypted.failures.len(), 1);
        assert!(matches!(
            decrypted
                .failures
                .get(&FieldId("bad_doc".to_string()))
                .unwrap(),
            AlloyError::InvalidInput { .. }
        ));
        assert_eq!(
            decrypted
                .successes
                .get(&FieldId("field".to_string()))
                .unwrap()
                .plaintext_field,
            get_plaintext().plaintext_field
        );
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_batch_failure() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = AlloyMetadata::new_simple(TenantId("bad-tenant".to_string()));
        let fields = PlaintextFields([(FieldId("field".to_string()), plaintext)].into());
        let err = get_client()
            .deterministic()
            .encrypt_batch(fields, &metadata)
            .await
            .unwrap_err();
        assert!(matches!(err, AlloyError::TspError { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_generate_query_field_values_known() -> TestResult {
        let plaintext = get_plaintext();
        let fields = PlaintextFields([(FieldId("field".to_string()), plaintext)].into());
        let metadata = get_metadata();
        let resp = get_client()
            .deterministic()
            .generate_query_field_values(fields, &metadata)
            .await?;
        let queries = resp.0.get(&FieldId("field".to_string())).unwrap();
        assert_eq!(queries.len(), 1);
        let expected = get_ciphertext().encrypted_field;
        assert_eq!(queries[0].encrypted_field, expected);
        assert_eq!(queries[0].secret_path.0, "secret");
        assert_eq!(queries[0].derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_rotate_fields_no_op() -> TestResult {
        let ciphertext = get_ciphertext();
        let fields = EncryptedFields([("field".to_string(), ciphertext)].into());
        let metadata = get_metadata();
        let mut resp = get_client()
            .deterministic()
            .rotate_fields(fields, &metadata, None)
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp
            .successes
            .remove(&FieldId("field".to_string()))
            .unwrap();
        let decrypted = get_client()
            .deterministic()
            .decrypt(rotated, &metadata)
            .await?;
        let expected = get_plaintext().plaintext_field;
        assert_eq!(decrypted.plaintext_field, expected);
        assert_eq!(decrypted.secret_path.0, "secret");
        assert_eq!(decrypted.derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn deterministic_rotate_fields_new_tenant() -> TestResult {
        let ciphertext = get_ciphertext();
        let fields = EncryptedFields([("field".to_string(), ciphertext)].into());
        let metadata = get_metadata();
        let new_tenant_id = TenantId("tenant-aws-l".to_string());
        let mut resp = get_client()
            .deterministic()
            .rotate_fields(fields, &metadata, Some(new_tenant_id.clone()))
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp
            .successes
            .remove(&FieldId("field".to_string()))
            .unwrap();
        let new_metadata = AlloyMetadata::new_simple(new_tenant_id);
        let decrypted = get_client()
            .deterministic()
            .decrypt(rotated, &new_metadata)
            .await?;
        let expected = get_plaintext().plaintext_field;
        assert_eq!(decrypted.plaintext_field, expected);
        assert_eq!(decrypted.secret_path.0, "secret");
        assert_eq!(decrypted.derivation_path.0, "deriv");
        Ok(())
    }
}
