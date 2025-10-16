mod common;

#[cfg(feature = "integration_tests")]
mod tests {
    use crate::common::{TestResult, get_client};
    use approx::assert_ulps_eq;
    use ironcore_alloy::{
        AlloyMetadata, DerivationPath, SecretPath, TenantId,
        errors::AlloyError,
        vector::{
            EncryptedVector, EncryptedVectors, PlaintextVector, PlaintextVectors, VectorId,
            VectorOps,
        },
    };
    use std::{iter, sync::Arc};

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
            encrypted_vector: vec![1.9443791, 1.0083799, 2.8500426],
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
            paired_icl_info: vec![
                0, 0, 20, 0, 1, 0, 10, 12, 34, 82, 15, 231, 178, 250, 195, 106, 119, 167, 225, 189,
                18, 32, 155, 124, 97, 213, 47, 71, 125, 3, 233, 86, 104, 12, 76, 209, 230, 60, 252,
                149, 48, 220, 1, 143, 77, 176, 162, 115, 159, 156, 88, 155, 193, 7,
            ]
            .into(),
        }
    }

    #[tokio::test]
    async fn vector_encrypt_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let encrypted = get_client()
            .vector()
            .encrypt(plaintext.clone(), &metadata)
            .await?;
        assert_eq!(encrypted.encrypted_vector.len(), 3);
        assert_eq!(encrypted.paired_icl_info.0.len(), 54);
        assert_eq!(encrypted.secret_path.0, "secret");
        assert_eq!(encrypted.derivation_path.0, "deriv");
        assert_ne!(plaintext.plaintext_vector, encrypted.encrypted_vector);
        Ok(())
    }

    #[tokio::test]
    async fn vector_decrypt_known() -> TestResult {
        let encrypted = get_ciphertext();
        let metadata = get_metadata();
        let decrypted = get_client().vector().decrypt(encrypted, &metadata).await?;
        let expected = get_plaintext();
        assert_eq!(decrypted.plaintext_vector, expected.plaintext_vector);
        Ok(())
    }

    #[tokio::test]
    async fn vector_batch_roundtrip_works() -> TestResult {
        let plaintext = get_plaintext();
        let plaintext_2 = PlaintextVector {
            plaintext_vector: vec![1.0, 2.0, 3.0],
            secret_path: SecretPath("different_path".to_string()),
            derivation_path: DerivationPath("different_path".to_string()),
        };
        let metadata = get_metadata();
        let vectors = PlaintextVectors(
            [
                (VectorId("vector".to_string()), plaintext),
                (VectorId("vector_2".to_string()), plaintext_2),
            ]
            .into(),
        );
        let encrypted = get_client()
            .vector()
            .encrypt_batch(vectors, &metadata)
            .await?;
        assert_eq!(encrypted.successes.0.len(), 2);
        assert_eq!(encrypted.failures.len(), 0);
        let bad_encrypted = EncryptedVector {
            encrypted_vector: vec![1.0, 1.0, 1.0],
            secret_path: SecretPath("secret".to_string()),
            derivation_path: DerivationPath("deriv".to_string()),
            paired_icl_info: vec![0].into(),
        };
        let encrypted_vectors = EncryptedVectors(
            iter::once((VectorId("bad_vector".to_string()), bad_encrypted))
                .chain(encrypted.successes.0)
                .collect(),
        );
        let decrypted = get_client()
            .vector()
            .decrypt_batch(encrypted_vectors, &metadata)
            .await?;
        assert_eq!(decrypted.successes.0.len(), 2);
        assert_eq!(decrypted.failures.len(), 1);
        assert!(matches!(
            decrypted
                .failures
                .get(&VectorId("bad_vector".to_string()))
                .unwrap(),
            AlloyError::InvalidInput { .. }
        ));
        let result = decrypted
            .successes
            .0
            .get(&VectorId("vector".to_string()))
            .unwrap()
            .plaintext_vector
            .clone();
        assert_ulps_vec_eq(result, get_plaintext().plaintext_vector);
        Ok(())
    }

    #[tokio::test]
    async fn vector_generate_query_vectors_works() -> TestResult {
        let plaintext = get_plaintext();
        let metadata = get_metadata();
        let vectors_to_query =
            PlaintextVectors([(VectorId("vector".to_string()), plaintext.clone())].into());
        let mut all_queries = get_client()
            .vector()
            .generate_query_vectors(vectors_to_query, &metadata)
            .await?;
        assert!(all_queries.0.contains_key(&VectorId("vector".to_string())));
        let mut queries = all_queries
            .0
            .remove(&VectorId("vector".to_string()))
            .unwrap();
        assert_eq!(queries.len(), 1);
        let query = queries.remove(0);
        let decrypted = get_client().vector().decrypt(query, &metadata).await?;
        assert_ulps_vec_eq(decrypted.plaintext_vector, plaintext.plaintext_vector);
        Ok(())
    }

    #[tokio::test]
    async fn vector_get_in_rotation_prefix_no_key() -> TestResult {
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
        assert!(
            prefix_err
                .to_string()
                .contains("didn't have the requested key.")
        );
        Ok(())
    }

    #[tokio::test]
    async fn vector_rotate_fields_no_op() -> TestResult {
        let ciphertext = get_ciphertext();
        let vectors = EncryptedVectors([(VectorId("vector".to_string()), ciphertext)].into());
        let metadata = get_metadata();
        let mut resp = get_client()
            .vector()
            .rotate_vectors(vectors, &metadata, None)
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp
            .successes
            .remove(&VectorId("vector".to_string()))
            .unwrap();
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
        let vectors = EncryptedVectors([(VectorId("vector".to_string()), ciphertext)].into());
        let metadata = get_metadata();
        let new_tenant_id = TenantId("tenant-aws-l".to_string());
        let mut resp = get_client()
            .vector()
            .rotate_vectors(vectors, &metadata, Some(new_tenant_id.clone()))
            .await?;
        assert_eq!(resp.successes.len(), 1);
        assert_eq!(resp.failures.len(), 0);
        let rotated = resp
            .successes
            .remove(&VectorId("vector".to_string()))
            .unwrap();
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
