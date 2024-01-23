mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{get_client, TestResult};
    use ironcore_alloy::{
        deterministic::{DeterministicFieldOps, EncryptedField, PlaintextField},
        AlloyMetadata, DerivationPath, SecretPath, TenantId,
    };
    use std::sync::Arc;

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextField {
        PlaintextField {
            plaintext_field: vec![1, 2, 3],
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
        }
    }

    fn get_ciphertext() -> EncryptedField {
        EncryptedField {
            encrypted_field: vec![
                0, 0, 19, 254, 0, 0, 239, 4, 228, 214, 163, 141, 230, 11, 246, 120, 121, 38, 1,
                247, 206, 60, 35, 34, 195,
            ],
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
    async fn deterministic_generate_query_field_values_known() -> TestResult {
        let plaintext = get_plaintext();
        let fields = [("field".to_string(), plaintext)].into();
        let metadata = get_metadata();
        let resp = get_client()
            .deterministic()
            .generate_query_field_values(fields, &metadata)
            .await?;
        let queries = resp.get("field").unwrap();
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
        let fields = [("field".to_string(), ciphertext)].into();
        let metadata = get_metadata();
        let mut resp = get_client()
            .deterministic()
            .rotate_fields(fields, &metadata, None)
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp.successes.remove("field").unwrap();
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
        let fields = [("field".to_string(), ciphertext)].into();
        let metadata = get_metadata();
        let new_tenant_id = TenantId("tenant-aws-l".to_string());
        let mut resp = get_client()
            .deterministic()
            .rotate_fields(fields, &metadata, Some(new_tenant_id.clone()))
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp.successes.remove("field").unwrap();
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
