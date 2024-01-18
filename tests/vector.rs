mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{get_client, TestResult};
    use approx::assert_ulps_eq;
    use ironcore_alloy::{
        vector::{EncryptedVector, PlaintextVector, VectorOps},
        AlloyMetadata, DerivationPath, SecretPath, TenantId,
    };
    use std::sync::Arc;

    fn assert_ulps_vec_eq(vec1: Vec<f32>, vec2: Vec<f32>) -> () {
        if vec1.len() != vec2.len() {
            panic!("Vectors must be equal length");
        }
        let zipped = vec1.into_iter().zip(vec2);
        zipped.into_iter().for_each(|(f1, f2)| {
            assert_ulps_eq!(f1, f2, max_ulps = 4);
        })
    }

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("tenant-gcp-l".to_string()))
    }

    fn get_plaintext() -> PlaintextVector {
        PlaintextVector {
            plaintext_vector: vec![1.0, 2.0, 3.0],
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
        }
    }

    fn get_ciphertext() -> EncryptedVector {
        EncryptedVector {
            encrypted_vector: vec![6603509.0, 3720753.8, 11410740.0],
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
            paired_icl_info: vec![
                0, 0, 20, 0, 1, 0, 10, 12, 93, 90, 137, 229, 59, 92, 49, 169, 195, 149, 119, 254,
                18, 32, 89, 97, 57, 184, 245, 149, 102, 216, 193, 211, 108, 152, 133, 173, 42, 183,
                134, 13, 200, 254, 170, 233, 12, 54, 187, 169, 191, 177, 33, 22, 195, 110,
            ],
        }
    }

    #[tokio::test]
    async fn standard_encrypt_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client().vector().encrypt(plaintext, &metadata).await?;
        assert_eq!(encrypted.encrypted_vector.len(), 3);
        assert_eq!(encrypted.paired_icl_info.len(), 54);
        assert_eq!(encrypted.secret_path.0, "secret");
        assert_eq!(encrypted.derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn standard_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client().vector().decrypt(encrypted, &metadata).await?;
        let expected = get_plaintext();
        assert_eq!(decrypted.plaintext_vector, expected.plaintext_vector);
        Ok(())
    }

    #[tokio::test]
    async fn standard_encrypt_with_existing_edek_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let vectors_to_query = [("vector".to_string(), plaintext.clone())].into();
        let mut all_queries = get_client()
            .vector()
            .generate_query_vectors(vectors_to_query, &metadata)
            .await?;
        assert!(all_queries.contains_key("vector"));
        let mut queries = all_queries.remove("vector").unwrap();
        assert_eq!(queries.len(), 1);
        let query = queries.remove(0);
        let decrypted = get_client().vector().decrypt(query, &metadata).await?;
        assert_ulps_vec_eq(decrypted.plaintext_vector, plaintext.plaintext_vector);
        Ok(())
    }

    #[tokio::test]
    async fn standard_get_searchable_edek_prefix_no_rotation() -> TestResult {
        let metadata = get_metadata();
        let prefix_err = get_client()
            .vector()
            .get_in_rotation_prefix(
                SecretPath("secret".to_string()),
                DerivationPath("deriv".to_string()),
                &metadata,
            )
            .await
            .unwrap_err();
        assert!(prefix_err
            .to_string()
            .contains("didn't have the requested key."));
        Ok(())
    }

    #[tokio::test]
    async fn vector_rotate_fields_no_op() -> TestResult {
        let ciphertext = get_ciphertext();
        let vectors = [("vector".to_string(), ciphertext)].into();
        let metadata = get_metadata();
        let mut resp = get_client()
            .vector()
            .rotate_vectors(vectors, &metadata, None)
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp.successes.remove("vector").unwrap();
        let decrypted = get_client().vector().decrypt(rotated, &metadata).await?;
        let expected = get_plaintext().plaintext_vector;
        assert_eq!(decrypted.plaintext_vector, expected);
        assert_eq!(decrypted.secret_path.0, "secret");
        assert_eq!(decrypted.derivation_path.0, "deriv");
        Ok(())
    }

    #[tokio::test]
    async fn vector_rotate_fields_new_tenant() -> TestResult {
        let ciphertext = get_ciphertext();
        let vectors = [("vector".to_string(), ciphertext)].into();
        let metadata = get_metadata();
        let new_tenant_id = TenantId("tenant-aws-l".to_string());
        let mut resp = get_client()
            .vector()
            .rotate_vectors(vectors, &metadata, Some(new_tenant_id.clone()))
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp.successes.remove("vector").unwrap();
        let new_metadata = AlloyMetadata::new_simple(new_tenant_id);
        let decrypted = get_client()
            .vector()
            .decrypt(rotated, &new_metadata)
            .await?;
        let expected = get_plaintext().plaintext_vector;
        assert_ulps_vec_eq(decrypted.plaintext_vector, expected);
        assert_eq!(decrypted.secret_path.0, "secret");
        assert_eq!(decrypted.derivation_path.0, "deriv");
        Ok(())
    }
}
