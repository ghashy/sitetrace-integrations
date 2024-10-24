use serde::Serialize;
use time::Duration;

pub(crate) const SITETRACE_TIMEOUT_COOKIE: &str = "sitetrace_timeout";
pub(crate) const SITETRACE_COOKIE: &str = "sitetrace_uuid";
pub(crate) const DEFAULT_COOKIE_DURATION: Duration = Duration::weeks(2);

pub(crate) fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}

#[macro_export]
macro_rules! impl_debug {
    ($type:ident) => {
        use crate::utils::error_chain_fmt;
        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                error_chain_fmt(self, f)
            }
        }
    };
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
    Other,
}

impl From<&http::Method> for HttpMethod {
    fn from(value: &http::Method) -> Self {
        match value {
            &http::Method::GET => HttpMethod::Get,
            &http::Method::POST => HttpMethod::Post,
            &http::Method::PUT => HttpMethod::Put,
            &http::Method::DELETE => HttpMethod::Delete,
            &http::Method::HEAD => HttpMethod::Head,
            &http::Method::OPTIONS => HttpMethod::Options,
            &http::Method::CONNECT => HttpMethod::Connect,
            &http::Method::PATCH => HttpMethod::Patch,
            &http::Method::TRACE => HttpMethod::Trace,
            m => {
                tracing::warn!("Got non-standard http method: {m}");
                HttpMethod::Other
            }
        }
    }
}
