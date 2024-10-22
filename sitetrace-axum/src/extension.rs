use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::{request::Parts, StatusCode};
use reqwest::Client;

use crate::{api_calls, config::Config, impl_debug};

pub type HitId = i32;
pub type TargetId = i32;

#[derive(thiserror::Error)]
pub enum STError {
    #[error("Target id is not owned by api_key user")]
    UnownedTargetId,
    #[error("Failed to send api call to the sitetrace")]
    FailedRequest,
    #[error("Failed to parse response")]
    CantParseResponse,
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
    /// task using `tokio::spawn`.
    pub async fn make_hit(
        &self,
        target_id: TargetId,
    ) -> Result<HitId, STError> {
        api_calls::make_hit(&self.web_client, &self.config, target_id).await
    }

    /// Returns count of active sessions
    pub async fn get_sessions_count(&self) -> Result<i64, STError> {
        api_calls::get_sessions_count(&self.web_client, &self.config).await
    }

    /// Run test request
    pub async fn run_test_req(&self) -> Result<(), STError> {
        api_calls::test_request(&self.web_client).await
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
