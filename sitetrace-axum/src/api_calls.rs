use std::future::Future;

use futures::TryFutureExt;
use reqwest::Client;
use secrecy::ExposeSecret;
use url::Url;
use uuid::Uuid;

use crate::{
    config::Config,
    middleware::{CreateSessionRequest, RequestData, RequestsPayload},
    STError,
};

pub(crate) fn touch_session<ST>(
    web_client: &Client,
    config: &Config<ST>,
    uuid: &Uuid,
) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> {
    web_client
        .post(
            config
                .server_url
                .join(&format!("/service-api/session/{}/touch", uuid))
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .send()
}

pub(crate) async fn create_session<'a, ST>(
    web_client: &Client,
    config: &Config<ST>,
    req: &CreateSessionRequest<'a>,
) -> Result<Uuid, reqwest::Error> {
    let uuid = web_client
        .post(
            config
                .server_url
                .join("/service-api/session/create")
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .json(req)
        .send()
        .await?
        .text()
        .await?
        .parse()
        .unwrap();
    Ok(uuid)
}

pub(crate) async fn get_sessions_count<ST>(
    web_client: &Client,
    config: &Config<ST>,
) -> Result<i64, STError> {
    let url = config.server_url.join("service-api/session/count").unwrap();
    let count = web_client
        .get(url)
        .bearer_auth(config.api_key.expose_secret())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get sessions count: {e}");
            STError::FailedRequest
        })?
        .text()
        .map_err(|e| {
            tracing::error!("Failed to parse response as text: {e}");
            STError::CantParseResponse
        })
        .await?
        .parse::<i64>()
        .map_err(|e| {
            tracing::error!("Failed to parse response text as i64: {e}");
            STError::CantParseResponse
        })?;
    Ok(count)
}

pub(crate) fn post_requests<ST>(
    client: &Client,
    config: &Config<ST>,
    payload: Vec<RequestData>,
) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> {
    client
        .post(
            config
                .server_url
                .join("service-api/trace-requests")
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .json(&payload)
        .send()
}

pub(crate) async fn make_hit<ST>(
    web_client: &Client,
    config: &Config<ST>,
    target_id: &str,
) -> Result<(), STError> {
    web_client
        .post(
            config
                .server_url
                .join(&format!("service-api/hit/{}", target_id))
                .unwrap(),
        )
        .bearer_auth(config.api_key.expose_secret())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to mark action: {e}");
            STError::FailedRequest
        })?;
    Ok(())
}

pub(crate) async fn test_request(web_client: &Client) -> Result<(), STError> {
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
            STError::FailedRequest
        })?;
    dbg!(resp);
    Ok(())
}