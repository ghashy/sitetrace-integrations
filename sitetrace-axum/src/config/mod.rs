use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{body::Body, extract::ConnectInfo, http::Request};
use futures::future::BoxFuture;
use http::header::{HOST, USER_AGENT};
use http::{Extensions, HeaderMap};
use secrecy::SecretString;
use strategy::SendRequestStrategy;
use url::Url;

use cookie::CookieConfig;

pub(crate) mod cookie;
pub(crate) mod strategy;

type Closure<T> = dyn for<'a> Fn(&Request<Body>) -> T + Send + Sync;

#[derive(Clone)]
pub struct Config<ST> {
    pub(super) api_key: SecretString,
    pub(super) send_strategy: SendRequestStrategy,
    pub(super) ignore_paths: regex::RegexSet,
    pub(super) server_url: Url,
    pub(super) get_hostname: Arc<Closure<Option<String>>>,
    pub(super) get_ip_address: Arc<Closure<Option<String>>>,
    pub(super) get_path: Arc<Closure<String>>,
    pub(super) get_user_agent: Arc<Closure<Option<String>>>,
    pub(super) get_user_id: Arc<
        Box<
            dyn Fn(ST, HeaderMap) -> BoxFuture<'static, Option<String>>
                + Send
                + Sync,
        >,
    >,
    pub(super) exec: Arc<
        Box<
            dyn Fn(
                    BoxFuture<
                        'static,
                        Result<reqwest::Response, reqwest::Error>,
                    >,
                ) -> ()
                + Send
                + Sync,
        >,
    >,
    pub(super) cookie_config: CookieConfig<'static>,
}

impl<ST> Default for Config<ST> {
    fn default() -> Self {
        Self {
            api_key: Default::default(),
            send_strategy: SendRequestStrategy::default(),
            server_url: "https://api.сайтотряс.рф".parse().unwrap(),
            get_hostname: Arc::new(get_hostname),
            get_ip_address: Arc::new(get_ip_address),
            get_path: Arc::new(get_path),
            get_user_agent: Arc::new(get_user_agent),
            get_user_id: Arc::new(Box::new(|_: ST, _: HeaderMap| {
                Box::pin(async move { None })
            })),
            cookie_config: Default::default(),
            ignore_paths: regex::RegexSet::empty(),
            exec: Arc::new(Box::new(|_| {
                panic!("future exec function is not provided!");
            })),
        }
    }
}

fn get_hostname(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok().map(|s| s.to_owned()))
}

fn get_ip_address(req: &Request<Body>) -> Option<String> {
    let extensions = req.extensions();
    let headers = req.headers();
    if let Some(val) = ip_from_x_real_ip(headers) {
        Some(val.to_string())
    } else if let Some(val) = ip_from_x_forwarded_for(headers) {
        Some(val.to_string())
    } else {
        ip_from_connect_info(extensions).map(|val| val.to_string())
    }
}

fn ip_from_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| {
            s.split(',')
                .rev()
                .find_map(|s| s.trim().parse::<IpAddr>().ok())
        })
}

fn ip_from_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
}

fn ip_from_connect_info(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn get_path(req: &Request<Body>) -> String {
    req.uri().path().to_owned()
}

fn get_user_agent(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(USER_AGENT)
        .and_then(|h| h.to_str().ok().map(|s| s.to_owned()))
}

pub(crate) fn get_full_url(req: &Request<Body>) -> Option<String> {
    let Some(host) = get_hostname(&req) else {
        return None;
    };

    // Get the scheme
    let Some(scheme) = req.uri().scheme_str() else {
        return None;
    };

    // Build full URL
    let full_url = format!(
        "{}://{}/{}{}",
        scheme,
        host,
        req.uri().path(),
        req.uri()
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default()
    );
    Some(full_url)
}
