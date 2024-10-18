use time::Duration;

pub(crate) const PROLONG_PATH: &str = "/sitetrace_prolong";
pub(crate) const LOG_REQUEST_PATH: &str = "api/log-request";
pub(crate) const HIT_PATH: &str = "api/action";
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
