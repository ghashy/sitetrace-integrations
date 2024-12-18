use std::future::Future;

use futures::{FutureExt, TryFutureExt};
use reqwest::Client;
use secrecy::ExposeSecret;
use url::Url;
use uuid::Uuid;

use crate::{
    config::{Config, ExecOutput},
    extension::{HitId, TargetId},
    middleware::{RequestsPayload, SessionData},
    SiteTraceError,
};

pub(crate) fn touch_session<'a, ST>(
    web_client: &Client,
    config: &Config<ST>,
    uuid: &Uuid,
    req: &SessionData<'a>,
) -> impl Future<Output = ExecOutput> {
    web_client
        .post(
            config
                .server_url
                .join(&format!("/api/v1/service/session/{}/touch", uuid))
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .json(req)
        .send()
        .then(|r| async { ExecOutput::Response(r) })
}

pub(crate) async fn create_session<'a, ST>(
    web_client: &Client,
    config: &Config<ST>,
    req: &SessionData<'a>,
) -> Result<Uuid, reqwest::Error> {
    let uuid = web_client
        .post(config.server_url.join("/api/v1/service/session").unwrap())
        .bearer_auth(config.api_key.expose_secret())
        .json(req)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?
        .parse()
        .unwrap();
    Ok(uuid)
}

pub(crate) async fn get_sessions_count<ST>(
    web_client: &Client,
    config: &Config<ST>,
    host: &str,
) -> Result<i64, SiteTraceError> {
    let url = config
        .server_url
        .join("/api/v1/service/session/count")
        .unwrap();
    let count = web_client
        .get(url)
        .query(&["host", host])
        .bearer_auth(config.api_key.expose_secret())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get sessions count: {e}");
            SiteTraceError::FailedRequest
        })?
        .text()
        .map_err(|e| {
            tracing::error!("Failed to parse response as text: {e}");
            SiteTraceError::CantParseResponse
        })
        .await?
        .parse::<i64>()
        .map_err(|e| {
            tracing::error!("Failed to parse response text as i64: {e}");
            SiteTraceError::CantParseResponse
        })?;
    Ok(count)
}

pub(crate) fn post_requests<ST>(
    client: &Client,
    config: &Config<ST>,
    payload: RequestsPayload,
) -> impl Future<Output = ExecOutput> {
    client
        .post(config.server_url.join("/api/v1/service/requests").unwrap())
        .bearer_auth(config.api_key.expose_secret())
        .json(&payload)
        .send()
        .then(|r| async { ExecOutput::Response(r) })
}

pub(crate) async fn make_hit<ST>(
    web_client: &Client,
    config: &Config<ST>,
    target_id: TargetId,
) -> Result<HitId, SiteTraceError> {
    let hit_id = web_client
        .post(
            config
                .server_url
                .join(&format!("/api/v1/service/target/{}/hit", target_id))
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to mark action: {e}");
            SiteTraceError::FailedRequest
        })?
        .text()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get hit_id text body from response: {e}"
            );
            SiteTraceError::FailedRequest
        })?
        .parse()
        .map_err(|e| {
            tracing::error!("Failed to parse hit_id: {e}");
            SiteTraceError::FailedRequest
        })?;
    Ok(hit_id)
}

pub(crate) async fn test_request(
    web_client: &Client,
) -> Result<(), SiteTraceError> {
    let url = "http://localhost:8000"
        .parse::<Url>()
        .unwrap()
        .join("/api/protected/test_apitokenauth")
        .unwrap();
    let resp = web_client
        .post(url)
        .bearer_auth("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run test request: {e}");
            SiteTraceError::FailedRequest
        })?;
    dbg!(resp);
    Ok(())
}
