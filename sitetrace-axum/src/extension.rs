use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::{request::Parts, StatusCode};
use reqwest::Client;

use crate::{config::Config, impl_debug, utils::HIT_PATH};

#[derive(thiserror::Error)]
pub enum STError {
    #[error("Target id is not owned by api_key user")]
    UnownedTargetId,
    #[error("Failed to send api call to the sitetrace")]
    FailedRequest,
}

impl_debug!(STError);

/// The extension is designed to interact with
/// SiteTrace API from within handlers.
#[derive(Clone)]
pub struct SiteTraceExt<ST = ()> {
    web_client: Client,
    config: Config<ST>,
}

impl<ST> SiteTraceExt<ST> {
    pub(crate) fn new(config: Config<ST>) -> Self {
        SiteTraceExt {
            web_client: Client::new(),
            config,
        }
    }

    /// It is highly recommended to call the method within a background
    /// task using `tokio::spawn` or similar mechanisms.
    /// This ensures that the Axum handler can return a response to the
    /// client promptly, without being blocked by the API call.
    pub async fn make_hit(&self, target_id: &str) -> Result<(), STError> {
        let mut url = self.config.server_url.join(HIT_PATH).unwrap();
        url.set_query(Some(target_id));
        self.web_client.post(url).send().await.map_err(|e| {
            tracing::error!("Failed to mark action: {e}");
            STError::FailedRequest
        })?;
        Ok(())
    }
}

#[async_trait]
impl<S, ST> FromRequestParts<S> for SiteTraceExt<ST>
where
    S: Sync + Send + std::fmt::Debug,
    ST: 'static + Clone,
{
    type Rejection = (http::StatusCode, &'static str);

    #[tracing::instrument]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<SiteTraceExt<ST>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract SitetraceExt. Is `SitetraceLayer` enabled?",
        ))
    }
}
