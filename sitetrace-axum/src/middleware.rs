use std::task::{Context, Poll};
use std::{pin::Pin, sync::Arc};
use std::{sync::OnceLock, time::Instant};

use axum::{body::Body, http::Request, response::Response};
use core::panic;
use futures::lock::Mutex;
use futures::{Future, FutureExt};
use garde::Validate;
use http::HeaderMap;
use regex::RegexSet;
use serde::Serialize;
use time::format_description::well_known::iso8601::{self, TimePrecision};
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;
use tower::{Layer, Service};
use tower_cookies::CookieManager;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use crate::api_calls::{create_session, post_requests, touch_session};
use crate::config::{get_full_url, Config};
use crate::extension::SiteTraceExt;
use crate::utils::{HttpMethod, PROLONG_PATH};
use crate::{CookieConfig, SendRequestStrategy};

const SIMPLE_ISO: Iso8601<6651332276402088934156738804825718784> = Iso8601::<
    {
        iso8601::Config::DEFAULT
            .set_year_is_six_digits(false)
            .set_time_precision(TimePrecision::Second {
                decimal_digits: None,
            })
            .encode()
    },
>;
time::serde::format_description!(iso_format, OffsetDateTime, SIMPLE_ISO);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CreateSessionRequest<'a> {
    ip: &'a Option<String>,
    hostname: &'a Option<String>,
    user_agent: &'a Option<String>,
}

#[derive(Debug, Clone, Serialize, Validate)]
#[garde(allow_unvalidated)]
pub(crate) struct RequestData {
    #[serde(with = "iso_format")]
    created_at: OffsetDateTime,
    path: String,
    method: HttpMethod,
    response_time_ms: u32,
    status: u16,
    #[garde(inner(length(max = 100)))]
    hostname: Option<String>,
    ip_address: Option<String>,
    #[garde(inner(length(max = 100)))]
    user_agent: Option<String>,
    #[garde(inner(length(max = 100)))]
    user_id: Option<String>,
    session_uuid: Option<Uuid>,
    #[garde(inner(length(max = 1000)))]
    full_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Validate)]
pub(crate) struct RequestsPayload {
    #[garde(length(min = 1, max = 5000))]
    requests: Vec<RequestData>,
}

pub fn requests_static() -> &'static Mutex<Vec<RequestData>> {
    static REQUESTS: OnceLock<Mutex<Vec<RequestData>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn last_posted_static() -> &'static Mutex<Instant> {
    static LAST: OnceLock<Mutex<Instant>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new(Instant::now()))
}

/// Hint: to allow use cookies for SiteTrace service, just set any cookie for client.
/// If 'cookie' field is found in request headers, cookies are considered allowed.
#[derive(Clone)]
pub struct SiteTraceLayer<ST = ()> {
    config: Config<ST>,
    app_state: Option<ST>,
}

pub struct SiteTraceLayerBuilder<'a, ST = ()> {
    config: Config<ST>,
    app_state: Option<ST>,
    ignore_paths: Vec<&'a str>,
}

impl<'a, ST> SiteTraceLayerBuilder<'a, ST> {
    /// Creates a new instance of `SiteTraceLayer`.
    ///
    /// This function takes an API key to start constructing `SiteTraceLayer`.
    ///
    /// # Parameters
    ///
    /// - `api_key`: A `String` representing the API key that will be used for making requests.
    ///
    /// # Returns
    ///
    /// Returns an instance of `SiteTraceLayerBuilder` configured with the provided API key.
    pub fn new(api_key: String) -> Self {
        let mut config = Config::default();
        config.api_key = api_key.into();
        Self {
            config,
            app_state: None,
            ignore_paths: Vec::new(),
        }
    }

    /// Build a new instance of `SiteTraceLayer`.
    ///
    /// This function takes a closure (`fut`) that allows you to define how to handle
    /// a background asynchronous task. The closure is called with a future that resolves to a
    /// `reqwest::Response` or an error. This enables integration with the asynchronous environment,
    /// avoiding blocking the response while processing the request in the background.
    ///
    /// # Parameters
    ///
    /// - `fut`: A closure that takes a pinned future as an argument and returns `()`.
    ///
    /// # Returns
    ///
    /// Returns an instance of `SiteTraceLayer` configured with the provided API key and execution
    /// closure.
    ///
    /// # Example
    ///
    /// Here's how to use the `build_with_exec` function to create a `SiteTraceLayer` that spawns a background
    /// task to handle a request asynchronously without blocking the response:
    ///
    /// ```rust
    /// use sitetrace-axum::SiteTraceLayer;
    ///
    /// let layer: SiteTraceLayer<()> =
    ///     SiteTraceLayerBuilder::new("apikey".to_owned())
    ///         .build_with_exec(|fut| {
    ///             tokio::spawn(async move {
    ///                 match fut.await {
    ///                     Ok(r) = {
    ///                         dbg!(r);
    ///                     }
    ///                     Err(e) = {
    ///                         tracing::error!(
    ///                             "Failed to send api call to sitetrace: {e}"
    ///                         );
    ///                     }
    ///                 }
    ///            });
    ///         })
    ///         .unwrap();
    /// ```
    ///
    /// In this example, the `fut` future is awaited in a Tokia task, allowing the middleware
    /// to return response while handling the result of the api call response in the background.
    pub fn build_with_exec<F>(
        mut self,
        fut: F,
    ) -> Result<SiteTraceLayer<ST>, regex::Error>
    where
        F: Fn(
                Pin<
                    Box<
                        dyn Future<
                                Output = Result<
                                    reqwest::Response,
                                    reqwest::Error,
                                >,
                            > + Send
                            + 'static,
                    >,
                >,
            ) -> ()
            + Send
            + Sync
            + Clone
            + 'static,
        ST: Send + 'static,
    {
        self.config.exec = Arc::new(Box::new(fut));
        let regex_set = RegexSet::new(self.ignore_paths)?;
        self.config.ignore_paths = regex_set;

        Ok(SiteTraceLayer {
            config: self.config,
            app_state: self.app_state,
        })
    }

    /// Assigns the application state to the `SiteTraceLayer`.
    ///
    /// This method allows you to provide a state object that can be used by other methods for
    /// context-dependent processing, such as handling user IDs or interacting with service backends
    /// like PostgreSQL or Redis.
    ///
    /// # Parameters
    /// - `state`: An instance of the application state (`ST`) that will be stored and utilized
    ///   by the `SiteTraceLayer`.
    pub fn with_app_state(mut self, state: ST) -> Self {
        self.app_state = Some(state);
        self
    }

    /// Sets the server URL for the `SiteTraceLayer`.
    ///
    /// This method allows you to specify the base URL of the server that the `SiteTraceLayer`
    /// will interact with. The path of the URL will be automatically cleared to ensure a clean
    /// configuration.
    ///
    /// # Parameters
    /// - `server_url`: A `Url` object representing the server's base URL to be used in
    ///   subsequent requests.
    pub fn with_server_url(mut self, mut server_url: Url) -> Self {
        server_url.set_path("");
        self.config.server_url = server_url;
        self
    }

    /// Sets a hostname mapping function for the `SiteTraceLayer`.
    ///
    /// This method enables the configuration of a closure that can extract a hostname from
    /// incoming requests. This allows further customization of how hostnames are processed
    /// within the service.
    ///
    /// # Parameters
    /// - `mapper`: A closure that takes a reference to a `Request<Body>` and returns an optional
    ///   hostname as a `String`. This closure should implement the `Send`, `Sync`, and `'static` traits.
    pub fn with_hostname_mapper<F>(mut self, mapper: F) -> Self
    where
        F: Fn(&Request<Body>) -> Option<String> + Send + Sync + 'static,
    {
        self.config.get_hostname = Arc::new(mapper);
        self
    }

    /// Sets a closure to extract the IP address from the request.
    ///
    /// # Parameters
    /// - `mapper`: A closure that takes a `Request<Body>` and returns an optional IP address as a `String`.
    pub fn with_ip_address_mapper<F>(mut self, mapper: F) -> Self
    where
        F: Fn(&Request<Body>) -> Option<String> + Send + Sync + 'static,
    {
        self.config.get_ip_address = Arc::new(mapper);
        self
    }

    /// Sets a closure to determine the path from the request.
    ///
    /// # Parameters
    /// - `mapper`: A closure that takes a `Request<Body>` and returns the path as a `String`.
    pub fn with_path_mapper<F>(mut self, mapper: F) -> Self
    where
        F: Fn(&Request<Body>) -> String + Send + Sync + 'static,
    {
        self.config.get_path = Arc::new(mapper);
        self
    }

    /// Sets a closure to extract the User-Agent string from the request.
    ///
    /// # Parameters
    /// - `mapper`: A closure that takes a `Request<Body>` and returns an optional User-Agent as a `String`.
    pub fn with_user_agent_mapper<F>(mut self, mapper: F) -> Self
    where
        F: Fn(&Request<Body>) -> Option<String> + Send + Sync + 'static,
    {
        self.config.get_user_agent = Arc::new(mapper);
        self
    }

    /// Sets the cookie configuration.
    ///
    /// # Parameters
    /// - `config`: A `CookieConfig` to configure how cookies are handled.
    pub fn with_cookie_config(mut self, config: CookieConfig<'static>) -> Self {
        self.config.cookie_config = config;
        self
    }

    /// Sets the send request strategy.
    ///
    /// Set how to determine that it is time for sending
    /// cached requests pack to the SiteTrace service.
    ///
    /// # Parameters
    /// - `strategy`: A `SendRequestStrategy` strategy.
    pub fn with_send_request_strategy(
        mut self,
        strategy: SendRequestStrategy,
    ) -> Self {
        self.config.send_strategy = strategy;
        self
    }

    /// Adds a path to the ignore list.
    ///
    /// Paths should start with `/`, e.g., `/mypath`.
    /// Path is a regex, so it could match all subroutes.
    ///
    /// # Parameters
    /// - `path`: The path to ignore.
    pub fn ignore_path(mut self, path: &'static str) -> Self {
        self.ignore_paths.push(path);
        self
    }

    /// Provides a closure to map user IDs based on the application state.
    ///
    /// This method enables the specification of a user ID mapper function that will be invoked
    /// with the application state (`ST`) and the `HeaderMap`. This allows the service to handle
    /// user identification.
    ///
    /// # Parameters
    /// - `mapper`: A closure that takes the application state and header data, returning an optional
    ///   user ID as a `String`.
    ///
    /// # Panics
    /// This method will panic if the `app_state` is `None`.
    ///
    /// # Safety
    /// The user must ensure that the `app_state` is initialized before invoking this method to avoid
    /// potential panics during runtime.
    pub fn with_get_user_id_mapper<F, Fut>(mut self, mapper: F) -> Self
    where
        F: Fn(ST, HeaderMap) -> Fut + Send + Sync + Clone + 'static,
        ST: Send + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        if self.app_state.is_some() {
            self.config.get_user_id = Arc::new(Box::new(move |state, s| {
                let mapper = mapper.clone();
                Box::pin(async move { mapper(state, s).await })
            }));
        } else {
            panic!("State should be set!")
        }
        self
    }
}

impl<S, ST> Layer<S> for SiteTraceLayer<ST>
where
    ST: Clone,
{
    type Service = CookieManager<SiteTraceManager<S, ST>>;

    fn layer(&self, inner: S) -> Self::Service {
        let manager = SiteTraceManager {
            config: self.config.clone(),
            inner,
            web_client: reqwest::Client::new(),
            app_state: self.app_state.clone(),
        };
        CookieManager::new(manager)
    }
}

#[derive(Clone)]
pub struct SiteTraceManager<S, ST> {
    inner: S,
    config: Config<ST>,
    web_client: reqwest::Client,
    app_state: Option<ST>,
}

impl<S, ST> Service<Request<Body>> for SiteTraceManager<S, ST>
where
    ST: Clone + Send + Sync + 'static,
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<Self::Response, Self::Error>>
                + Send
                + 'static,
        >,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let now = Instant::now();
        let created_at = OffsetDateTime::now_utc();
        let span = tracing::info_span!("sitetrace call");

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let client = self.web_client.clone();
        let config = self.config.clone();
        let hostname = (self.config.get_hostname)(&req);
        let ip_address = (self.config.get_ip_address)(&req);
        let path = (self.config.get_path)(&req);
        let method = req.method().into();
        let user_agent = (self.config.get_user_agent)(&req);
        let app_state = self.app_state.clone();

        Box::pin(
            async move {
                // Get user_id
                let user_id = if let Some(app_state) = app_state {
                    let headers = req.headers().clone();
                    (config.get_user_id)(app_state, headers).await
                } else {
                    None
                };

                let Some(cookies) =
                    req.extensions_mut().get_mut::<tower_cookies::Cookies>()
                else {
                    // In practice this should never happen because we wrap `CookieManager`
                    // directly.
                    tracing::error!("missing cookies request extension");
                    return Ok(Response::default());
                };

                let cookie_allowed = !cookies.list().is_empty();
                let mut uuid_to_send = None;
                if cookie_allowed {
                    let uuid = if let Some(c) =
                        cookies.get(&config.cookie_config.name)
                    {
                        let uuid = c.value();
                        uuid.parse().unwrap()
                    } else {
                        // Create a new uuid
                        match create_session(
                            &client,
                            &config,
                            &CreateSessionRequest {
                                ip: &ip_address,
                                hostname: &hostname,
                                user_agent: &user_agent,
                            },
                        )
                        .await
                        {
                            Ok(uuid) => {
                                let cookie = build_cookie(
                                    config.cookie_config.clone(),
                                    uuid,
                                );
                                cookies.add(cookie);
                                uuid
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to fetch uuid from sitetrace: {e}"
                                );
                                let res: Response = inner.call(req).await?;
                                return Ok(res);
                            }
                        }
                    };

                    uuid_to_send = Some(uuid);

                    // Not track request, return OK
                    if req.uri().path().eq(PROLONG_PATH) {
                        let send = touch_session(&client, &config, &uuid);
                        (config.exec)(send.boxed());
                        return Ok(Response::default());
                    }
                }

                let ext = SiteTraceExt::new(config.clone());
                req.extensions_mut().insert(ext);

                let should_trace_req =
                    !config.ignore_paths.is_match(req.uri().path());
                let full_url = get_full_url(&req);
                let res: Response = inner.call(req).await?;

                if should_trace_req {
                    let request_data = RequestData {
                        hostname,
                        ip_address,
                        path,
                        user_agent,
                        method,
                        user_id,
                        status: res.status().as_u16(),
                        response_time_ms: now
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .expect("Failed to cast u128 to u32"),
                        created_at,
                        session_uuid: uuid_to_send,
                        full_url,
                    };
                    if let Err(e) = request_data.validate() {
                        tracing::error!("Failed to validate request data: {e}");
                    } else {
                        let mut req_guard = requests_static().lock().await;
                        let mut instant_guard =
                            last_posted_static().lock().await;
                        let last_posted = instant_guard.elapsed();
                        *instant_guard = Instant::now();
                        drop(instant_guard);
                        req_guard.push(request_data);
                        if config
                            .send_strategy
                            .should_send(last_posted.as_secs(), req_guard.len())
                        {
                            let payload = req_guard.to_vec();
                            req_guard.clear();
                            let send = post_requests(&client, &config, payload);
                            (config.exec)(send.boxed());
                        }
                    }
                }
                Ok(res)
            }
            .instrument(span),
        )
    }
}

fn build_cookie(
    config: CookieConfig<'static>,
    uuid: Uuid,
) -> tower_cookies::Cookie {
    let exp = config.expiry_date();
    let mut cookie_builder =
        tower_cookies::Cookie::build((config.name, uuid.to_string()))
            .http_only(config.http_only)
            .same_site(config.same_site)
            .secure(config.secure)
            .expires(exp)
            .path(config.path)
            .permanent();
    if let Some(domain) = config.domain {
        cookie_builder = cookie_builder.domain(domain);
    }
    cookie_builder.build()
}
