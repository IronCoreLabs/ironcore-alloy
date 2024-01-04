use crate::tenant_security_client::{
    DerivationType, DeriveKeyChoice, DerivedKey, KeyDeriveResponse, SecretType,
    TenantSecurityClient,
};
use crate::{errors::AlloyError, AlloyMetadata, VectorEncryptionKey};
use crate::{DerivationPath, SecretPath};
use convert_case::Casing;
use ironcore_documents::v5::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
use std::collections::HashSet;

pub mod config;
pub mod deterministic;
pub mod standard;
pub mod standard_attached;
pub mod vector;

pub trait SaasShieldSecurityEventOps {
    /// Log the security event `event` to the tenant's log sink.
    /// If the event time is unspecified the current time will be used.
    async fn log_security_event(
        &self,
        event: SecurityEvent,
        metadata: &AlloyMetadata,
        event_time_millis: Option<i64>,
    ) -> Result<(), AlloyError>;
}

#[derive(Debug, uniffi::Enum)]
pub enum SecurityEvent {
    Admin { event: AdminEvent },
    Data { event: DataEvent },
    Periodic { event: PeriodicEvent },
    User { event: UserEvent },
    Custom { event: CustomEvent },
}

impl ToString for SecurityEvent {
    fn to_string(&self) -> String {
        match self {
            SecurityEvent::Admin { event } => event.to_string(),
            SecurityEvent::Data { event } => event.to_string(),
            SecurityEvent::Periodic { event } => event.to_string(),
            SecurityEvent::User { event } => event.to_string(),
            SecurityEvent::Custom { event } => event.to_string(),
        }
    }
}

#[derive(Debug, uniffi::Enum)]
pub enum AdminEvent {
    Add,
    ChangePermissions,
    ChangeSetting,
    Remove,
}

impl ToString for AdminEvent {
    fn to_string(&self) -> String {
        format!(
            "ADMIN_{}",
            format!("{:?}", self).to_case(convert_case::Case::ScreamingSnake)
        )
    }
}

#[derive(Debug, uniffi::Enum)]
pub enum UserEvent {
    Add,
    Suspend,
    Remove,
    Login,
    TimeoutSession,
    Lockout,
    Logout,
    ChangePermissions,
    ExpirePassword,
    ResetPassword,
    ChangePassword,
    RejectLogin,
    EnableTwoFactor,
    DisableTwoFactor,
    ChangeEmail,
    RequestEmailVerification,
    VerifyEmail,
}

impl ToString for UserEvent {
    fn to_string(&self) -> String {
        format!(
            "USER_{}",
            format!("{:?}", self).to_case(convert_case::Case::ScreamingSnake)
        )
    }
}

#[derive(Debug, uniffi::Enum)]
pub enum DataEvent {
    Import,
    Export,
    Encrypt,
    Decrypt,
    Create,
    Delete,
    DenyAccess,
    ChangePermissions,
}

impl ToString for DataEvent {
    fn to_string(&self) -> String {
        format!(
            "DATA_{}",
            format!("{:?}", self).to_case(convert_case::Case::ScreamingSnake)
        )
    }
}

#[derive(Debug, uniffi::Enum)]
pub enum PeriodicEvent {
    EnforceRetentionPolicy,
    CreateBackup,
}

impl ToString for PeriodicEvent {
    fn to_string(&self) -> String {
        format!(
            "PERIODIC_{}",
            format!("{:?}", self).to_case(convert_case::Case::ScreamingSnake)
        )
    }
}

/// A custom event. The event must have a screaming snake case name and cannot start with an `_`.
#[derive(Debug, uniffi::Record)]
pub struct CustomEvent {
    event_name: String,
}

impl CustomEvent {
    pub fn create(event_name: &str) -> Result<CustomEvent, AlloyError> {
        let regex =
            regex::Regex::new("^[A-Z_]+$").expect("Regex compilation is a development error");
        if !regex.is_match(event_name) || event_name.starts_with("_") {
            Err(AlloyError::InvalidInput(
                "CustomEvents must be screaming snake case and cannot start with _".to_string(),
            ))
        } else {
            Ok(CustomEvent {
                event_name: event_name.to_string(),
            })
        }
    }
}

impl ToString for CustomEvent {
    fn to_string(&self) -> String {
        format!("CUSTOM_{}", self.event_name,)
    }
}

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
    Ok(ironcore_documents::v5::key_id_header::get_prefix_bytes_for_search(key_id_header).into())
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

    // This test is meant to test each of the types as well as just a smattering of the elements
    // since we use a library to do the conversion of enum name to screaming snake case, this gives me confidence.
    #[test]
    fn test_to_string_events() {
        // AdminEvent
        assert_eq!(
            SecurityEvent::Admin {
                event: AdminEvent::Add
            }
            .to_string(),
            "ADMIN_ADD"
        );
        assert_eq!(
            SecurityEvent::Admin {
                event: AdminEvent::ChangePermissions
            }
            .to_string(),
            "ADMIN_CHANGE_PERMISSIONS"
        );

        // DataEvent
        assert_eq!(
            SecurityEvent::Data {
                event: DataEvent::Import
            }
            .to_string(),
            "DATA_IMPORT"
        );
        assert_eq!(
            SecurityEvent::Data {
                event: DataEvent::Export
            }
            .to_string(),
            "DATA_EXPORT"
        );
        assert_eq!(
            SecurityEvent::Data {
                event: DataEvent::ChangePermissions
            }
            .to_string(),
            "DATA_CHANGE_PERMISSIONS"
        );

        // PeriodicEvent
        assert_eq!(
            SecurityEvent::Periodic {
                event: PeriodicEvent::CreateBackup
            }
            .to_string(),
            "PERIODIC_CREATE_BACKUP"
        );

        // UserEvent
        assert_eq!(
            SecurityEvent::User {
                event: UserEvent::Add
            }
            .to_string(),
            "USER_ADD"
        );
        assert_eq!(
            SecurityEvent::User {
                event: UserEvent::TimeoutSession
            }
            .to_string(),
            "USER_TIMEOUT_SESSION"
        );
        assert_eq!(
            SecurityEvent::User {
                event: UserEvent::RequestEmailVerification
            }
            .to_string(),
            "USER_REQUEST_EMAIL_VERIFICATION"
        );

        // CustomEvent
        assert_eq!(
            SecurityEvent::Custom {
                event: CustomEvent::create("TEST_WITH_SOMETHING").unwrap()
            }
            .to_string(),
            "CUSTOM_TEST_WITH_SOMETHING"
        );
    }

    #[test]
    fn test_custom_create() {
        assert_eq!(
            CustomEvent::create("_THIS_FAILS").unwrap_err(),
            AlloyError::InvalidInput(
                "CustomEvents must be screaming snake case and cannot start with _".to_string()
            )
        );

        assert_eq!(
            CustomEvent::create("thisAlso").unwrap_err(),
            AlloyError::InvalidInput(
                "CustomEvents must be screaming snake case and cannot start with _".to_string()
            )
        );
    }
}
