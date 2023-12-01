use crate::tenant_security_client::{
    DerivationType, DeriveKeyChoice, DerivedKey, KeyDeriveResponse, SecretType,
    TenantSecurityClient,
};
use crate::{errors::AlloyError, AlloyMetadata, VectorEncryptionKey};
use crate::{DerivationPath, SecretPath};
use ironcore_documents::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
use std::collections::HashSet;

pub mod config;
pub mod deterministic;
pub mod standard;
pub mod standard_attached;
pub mod vector;

/// Calls the TSP to derive keys for many secret_path/derivation_path combinations.
/// Then converts the results to encryption keys and key IDs.
async fn derive_keys_many_paths(
    tenant_security_client: &TenantSecurityClient,
    request_metadata: &AlloyMetadata,
    paths: Vec<(SecretPath, DerivationPath)>,
    secret_type: SecretType,
) -> Result<KeyDeriveResponse, AlloyError> {
    let paths_map = paths
        .into_iter()
        .into_grouping_map_by(|x| x.0.clone())
        .fold(HashSet::new(), |mut set, _, (_, derivation_path)| {
            set.insert(derivation_path);
            set
        });

    let derived_keys = tenant_security_client
        .tenant_key_derive(
            paths_map,
            &request_metadata.clone().try_into()?,
            DerivationType::Sha512,
            secret_type,
        )
        .await?;
    Ok(derived_keys)
}

/// Converts a DerivedKey to an encryption Key (with scaling factor) and key ID
fn derived_key_to_vector_encryption_key(
    derived_key: &DerivedKey,
) -> Result<(KeyId, VectorEncryptionKey), AlloyError> {
    let key = if derived_key.derived_key.len() < 35 {
        Err(AlloyError::TenantSecurityError(
            "Derivation didn't return enough bytes. HMAC-SHA512 should always return 64 bytes, so the TSP is misbehaving.".to_string(),
        ))
    } else {
        let key_bytes = &derived_key.derived_key.0[..];
        Ok(VectorEncryptionKey::unsafe_bytes_to_key(key_bytes))
    }?;
    Ok((KeyId(derived_key.tenant_secret_id.0), key))
}

fn get_in_rotation_prefix_internal(
    derived_keys: &KeyDeriveResponse,
    secret_path: SecretPath,
    derivation_path: DerivationPath,
    edek_type: EdekType,
    payload_type: PayloadType,
) -> Result<Vec<u8>, AlloyError> {
    let key_id = derived_keys
        .get_key_for_path(&secret_path, &derivation_path, DeriveKeyChoice::InRotation)?
        .tenant_secret_id
        .0;
    let key_id_header = KeyIdHeader {
        key_id: KeyId(key_id),
        edek_type,
        payload_type,
    };
    Ok(ironcore_documents::key_id_header::get_prefix_bytes_for_search(key_id_header).into())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tenant_security_client::TenantSecretAssignmentId;
    use base64_type::Base64;
    use std::collections::HashMap;

    // helper function to create the nested hashmaps. Groups by the secret path string and the derivation path string creating the
    // derivation keys inside as it goes.
    fn create_in_rotation_struct(
        vec: Vec<(&str, &str, KeyId, bool)>,
    ) -> HashMap<SecretPath, HashMap<DerivationPath, Vec<DerivedKey>>> {
        let secret_path_to_derivation_vec = vec
            .into_iter()
            .map(|(secret_str, derivation_str, key_id, current)| {
                (
                    SecretPath(secret_str.to_string()),
                    (
                        DerivationPath(derivation_str.to_string()),
                        DerivedKey {
                            derived_key: Base64(vec![]),
                            tenant_secret_id: TenantSecretAssignmentId(key_id.0),
                            current,
                        },
                    ),
                )
            })
            .into_group_map();
        secret_path_to_derivation_vec
            .into_iter()
            .map(|(secret, v)| (secret, v.into_iter().into_group_map()))
            .collect()
    }

    #[tokio::test]
    async fn get_in_rotation_key_prefixes_works() {
        let secret_path = SecretPath("secret".to_string());
        let derived_keys = create_in_rotation_struct(vec![
            (secret_path.0.as_str(), "derivation", KeyId(1), true),
            (secret_path.0.as_str(), "derivation", KeyId(2), false),
        ]);
        let key_derive_response = KeyDeriveResponse {
            has_primary_config: true,
            derived_keys,
        };
        let result = get_in_rotation_prefix_internal(
            &key_derive_response,
            secret_path,
            DerivationPath("derivation".to_string()),
            EdekType::SaasShield,
            PayloadType::StandardEdek,
        )
        .unwrap();

        assert_eq!(
            result.to_vec(),
            KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(2))
                .write_to_bytes()
                .to_vec()
        );
    }
}
