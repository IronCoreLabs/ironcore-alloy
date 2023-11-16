use crate::{errors::AlloyError, Secret, SecretPath};
use ironcore_documents::key_id_header::KeyId;
use std::{collections::HashMap, sync::Arc};

/// A secret used by standalone mode to derive encryption keys.
#[derive(Debug, uniffi::Object)]
pub struct StandaloneSecret {
    pub(crate) id: u32,
    pub(crate) secret: Arc<Secret>,
}
#[uniffi::export]
impl StandaloneSecret {
    /// Create a standalone secret. The secret needs to be cryptographically random bytes.
    #[uniffi::constructor]
    pub fn new(id: i32, secret: Arc<Secret>) -> Arc<Self> {
        Arc::new(StandaloneSecret {
            id: id as u32,
            secret,
        })
    }
}
/// A collection of secrets for standalone standard mode used to derive encryption keys.
/// The primary secret id is used to look up the primary secret, which will be used for encrypting new documents.
/// The rest of the secrets will only be used to decrypt existing documents when encountered.
#[derive(Debug, uniffi::Object)]
pub struct StandardSecrets {
    pub(crate) primary_secret_id: Option<u32>,
    pub(crate) secrets: HashMap<u32, Secret>,
}
#[uniffi::export]
impl StandardSecrets {
    /// Create a collection of standard secrets.
    /// This will error if secret ids aren't unique or the primary secret id isn't in the secrets list.
    #[uniffi::constructor]
    pub fn new(
        primary_secret_id: Option<i32>,
        secrets: Vec<Arc<StandaloneSecret>>,
    ) -> Result<Arc<Self>, AlloyError> {
        let mut internal_secrets = HashMap::new();
        for standalone_secret in secrets.into_iter() {
            if internal_secrets
                .insert(
                    standalone_secret.id,
                    standalone_secret.secret.as_ref().clone(),
                )
                .is_some()
            {
                return Err(AlloyError::InvalidKey(format!(
                    "Duplicate secret id encountered while initializing Standalone mode: {}",
                    standalone_secret.id
                )));
            }
        }

        // check that the provided primary does in fact exist
        if let Some(id) = primary_secret_id {
            if internal_secrets.get(&(id as u32)).is_none() {
                return Err(AlloyError::InvalidKey(format!(
                    "Primary secret id not found in provided secrets: {id}"
                )));
            }
        }

        Ok(Arc::new(Self {
            primary_secret_id: primary_secret_id.map(|i| i as u32),
            secrets: internal_secrets,
        }))
    }
}

/// A single secret that allows for rotation within a secret path.
/// Used for Deterministic and Vector operations.
#[derive(Debug, uniffi::Object)]
pub struct RotatableSecret {
    pub(crate) current_secret: Option<Arc<StandaloneSecret>>,
    pub(crate) in_rotation_secret: Option<Arc<StandaloneSecret>>,
}

#[uniffi::export]
impl RotatableSecret {
    /// Create a rotating secret. This will error if both secrets are unset. If no secret for a path is desired, leave
    /// that path out of the configuration entirely instead.
    #[uniffi::constructor]
    pub fn new(
        current_secret: Option<Arc<StandaloneSecret>>,
        in_rotation_secret: Option<Arc<StandaloneSecret>>,
    ) -> Result<Arc<Self>, AlloyError> {
        if current_secret.is_none() && in_rotation_secret.is_none() {
            Err(AlloyError::InvalidKey(
                "Cannot create a RotatingSecret with no secrets.".to_string(),
            ))
        } else {
            Ok(Arc::new(Self {
                current_secret,
                in_rotation_secret,
            }))
        }
    }
}

// This impl is for non-uniffi functions
impl RotatableSecret {
    pub(crate) fn get_secret_with_id(&self, id: &KeyId) -> Option<Arc<StandaloneSecret>> {
        self.current_secret
            .iter()
            .chain(self.in_rotation_secret.iter())
            .find(|secret| secret.id == id.0)
            .cloned()
    }
}

#[derive(Debug, uniffi::Object)]
pub struct VectorSecret {
    pub(crate) approximation_factor: f32,
    pub(crate) secret: Arc<RotatableSecret>,
}
#[uniffi::export]
impl VectorSecret {
    /// The approximation factor should be chosen in a way that balances security with search performance.
    /// A higher approximation factor is more secure, but introduces more variance into encrypted embeddings,
    /// possibly leading to degraded performance. A lower bound for the approximation factor to start with is `sqrt(M)`,
    /// where M is the absolute value of the largest data point in the input embeddings.
    #[uniffi::constructor]
    pub fn new(approximation_factor: f32, secret: Arc<RotatableSecret>) -> Arc<Self> {
        Arc::new(Self {
            approximation_factor,
            secret,
        })
    }
}

/// Configuration for the standalone SDKs. Sets secrets and secret paths for the different SDK operations.
/// If usage of only one set of SDK operations is desired the others can be left as empty objects, and will error if
/// called in that state.
#[derive(Debug, uniffi::Object, Clone)]
pub struct StandaloneConfiguration {
    pub(crate) standard: Arc<StandardSecrets>,
    pub(crate) deterministic: Arc<HashMap<SecretPath, Arc<RotatableSecret>>>,
    pub(crate) vector: Arc<HashMap<SecretPath, Arc<VectorSecret>>>,
}
#[uniffi::export]
impl StandaloneConfiguration {
    #[uniffi::constructor]
    pub fn new(
        standard: Arc<StandardSecrets>,
        deterministic: HashMap<SecretPath, Arc<RotatableSecret>>,
        vector: HashMap<SecretPath, Arc<VectorSecret>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            standard,
            deterministic: Arc::new(deterministic),
            vector: Arc::new(vector),
        })
    }
}
