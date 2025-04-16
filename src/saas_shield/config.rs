use crate::tenant_security_client::TenantSecurityClient;
use crate::tenant_security_client::request::{AlloyHttpClientHeaders, HttpClient};
use crate::{errors::AlloyError, tenant_security_client::ApiKey};
use std::sync::Arc;

/// Configuration for the SaaS Shield SDKs. Sets the TSP domain/URI and API key to be used for SaaS Shield operations.
#[derive(uniffi::Object)]
pub struct SaasShieldConfiguration {
    // TODO: configuring this across the whole SDK probably isn't how we want to do it. If a vector was encrypted with
    //       an approximation factor, you wouldn't be able to query against/for it reliably if the factor changed in
    //       the future, or decrypt it. You'd have to manually know what factor the data you're looking for used and
    //       create this config with the same one. Not do-able outside full re-indexing situations.
    pub(crate) approximation_factor: Option<f32>,
    pub(crate) tenant_security_client: Arc<TenantSecurityClient>,
}
#[uniffi::export]
impl SaasShieldConfiguration {
    #[uniffi::constructor]
    pub fn new(
        tsp_uri: String,
        api_key: String,
        approximation_factor: Option<f32>,
        http_client: Arc<dyn HttpClient>,
    ) -> Result<Arc<Self>, AlloyError> {
        let parsed_api_key = ApiKey::try_from(api_key)?;
        let headers = AlloyHttpClientHeaders {
            content_type: "application/json".to_string(),
            authorization: format!("cmk {}", parsed_api_key.0),
        };
        // TODO(murph): need to put this on our rust calls? probably need to document that this setting should be on for any HttpClient
        // .danger_accept_invalid_certs(accept_invalid_certs)
        Ok(Arc::new(Self {
            approximation_factor,
            tenant_security_client: Arc::new(TenantSecurityClient::new(
                tsp_uri,
                http_client,
                headers,
            )),
        }))
    }
}
