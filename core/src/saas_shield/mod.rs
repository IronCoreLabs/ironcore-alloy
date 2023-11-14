use crate::tenant_security_client::{DerivationType, DerivedKey, SecretType, TenantSecurityClient};
use crate::{errors::CloakedAiError, IronCoreMetadata, Key};
use crate::{DerivationPath, SecretPath};
use ironcore_documents::key_id_header::KeyId;
use itertools::Itertools;
use std::collections::{HashMap, HashSet};

pub mod config;
pub mod deterministic;
pub mod standard;
pub mod vector;

pub(crate) enum DeriveKeyChoice {
    Current,
    Specific(KeyId),
    InRotation, // Non-current
}

/// Calls the TSP to derive keys for a single secret_path/derivation_path.
/// Then converts the result to an encryption key and key ID.
async fn derive_keys_for_path(
    tsc: &TenantSecurityClient,
    request_metadata: &IronCoreMetadata,
    secret_path: &SecretPath,
    deriv_path: &DerivationPath,
    derive_key_choice: DeriveKeyChoice,
    secret_type: SecretType,
) -> Result<(KeyId, Key), CloakedAiError> {
    let paths = [(secret_path.clone(), [deriv_path.clone()].into())].into();
    let derived_keys = tsc
        .tenant_key_derive(
            paths,
            &request_metadata.clone().try_into()?,
            DerivationType::Sha512,
            secret_type,
        )
        .await?;
    let derived_keys = match derive_key_choice {
        DeriveKeyChoice::Current => derived_keys.get_current(secret_path, deriv_path),
        DeriveKeyChoice::Specific(key_id) => {
            derived_keys.get_by_id(secret_path, deriv_path, key_id.0)
        }
        DeriveKeyChoice::InRotation => derived_keys.get_in_rotation(secret_path, deriv_path),
    }
    .ok_or_else(|| {
        CloakedAiError::TenantSecurityError(
            "The secret path, derivation path combo didn't have the requested key.".to_string(),
        )
    })?; // COLT: Maybe different errors in the if/else?
    derived_key_to_encryption_key(derived_keys)
}

/// Calls the TSP to derive keys for many secret_path/derivation_path combinations.
/// Then converts the results to encryption keys and key IDs.
async fn derive_keys_many_paths(
    tsc: &TenantSecurityClient,
    request_metadata: &IronCoreMetadata,
    paths: Vec<(SecretPath, DerivationPath)>,
    secret_type: SecretType,
) -> Result<HashMap<SecretPath, HashMap<DerivationPath, Vec<(KeyId, Key)>>>, CloakedAiError> {
    let paths_map = paths
        .into_iter()
        .into_grouping_map_by(|x| x.0.clone())
        .fold(HashSet::new(), |mut set, _, (_, derivation_path)| {
            set.insert(derivation_path);
            set
        });

    let derived_keys = tsc
        .tenant_key_derive(
            paths_map,
            &request_metadata.clone().try_into()?,
            DerivationType::Sha512,
            secret_type,
        )
        .await?;
    derived_keys
        .derived_keys
        .into_iter()
        .map(|(secret_path, derivation_paths)| {
            derivation_paths
                .into_iter()
                .map(|(derivation_path, derived_keys)| {
                    derived_keys
                        .into_iter()
                        .map(|key| derived_key_to_encryption_key(&key))
                        .try_collect()
                        .map(|res| (derivation_path, res))
                })
                .try_collect()
                .map(|res| (secret_path, res))
        })
        .try_collect()
}

/// Converts a DerivedKey to an encryption Key (with scaling factor) and key ID
fn derived_key_to_encryption_key(derived_key: &DerivedKey) -> Result<(KeyId, Key), CloakedAiError> {
    let key = if derived_key.derived_key.len() < 35 {
        Err(CloakedAiError::TenantSecurityError(
            "Derivation didn't return enough bytes. HMAC-SHA512 should always return 64 bytes, so the TSP is misbehaving.".to_string(),
        )) // COLT: better error
    } else {
        let key_bytes = &derived_key.derived_key.0[..];
        Ok(Key::unsafe_bytes_to_key(key_bytes))
    }?;
    Ok((KeyId(derived_key.tenant_secret_id.0), key))
}
