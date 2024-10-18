use std::borrow::Cow;

use time::{Duration, OffsetDateTime};
use tower_cookies::cookie::SameSite;

use crate::utils::{DEFAULT_COOKIE_DURATION, SITETRACE_COOKIE};

/// Session expiry configuration.
///
/// # Examples
///
/// ```rust
/// use time::{Duration, OffsetDateTime};
/// use sitetrace-axum::config::Expiry;
///
/// // Will be expired on "session end".
/// let expiry = Expiry::OnSessionEnd;
///
/// // Will be expired in five minutes from last acitve.
/// let expiry = Expiry::OnInactivity(Duration::minutes(5));
///
/// // Will be expired at the given timestamp.
/// let expired_at = OffsetDateTime::now_utc().saturating_add(Duration::weeks(2));
/// let expiry = Expiry::AtDateTime(expired_at);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// Expire on [current session end][current-session-end], as defined by the
    /// browser.
    ///
    /// [current-session-end]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#removal_defining_the_lifetime_of_a_cookie
    OnSessionEnd,

    /// Expire on inactivity.
    ///
    /// Reading a session is not considered activity for expiration purposes.
    /// [`Session`] expiration is computed from the last time the session was
    /// _modified_.
    OnInactivity(Duration),

    /// Expire at a specific date and time.
    ///
    /// This value may be extended manually with
    /// [`set_expiry`](Session::set_expiry).
    AtDateTime(OffsetDateTime),
}

#[derive(Clone, Debug)]
pub struct CookieConfig<'a> {
    pub(crate) name: Cow<'a, str>,
    pub(crate) http_only: bool,
    pub(crate) same_site: SameSite,
    pub(crate) expiry: Option<Expiry>,
    pub(crate) secure: bool,
    pub(crate) path: Cow<'a, str>,
    pub(crate) domain: Option<Cow<'a, str>>,
    pub(crate) always_save: bool,
}

impl CookieConfig<'static> {
    /// Configures the name of the cookie used for the session.
    /// The default value is `"id"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sitetrace-axum::SiteTraceLayer;
    ///
    /// let service = SiteTraceLayer::new("api_key").with_name("my-cookie-name");
    /// ```
    pub fn with_name<N: Into<Cow<'static, str>>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    /// Configures the `"HttpOnly"` attribute of the cookie used for the
    /// session.
    ///
    /// # ⚠️ **Warning: Cross-site scripting risk**
    ///
    /// Applications should generally **not** override the default value of
    /// `true`. If you do, you are exposing your application to increased risk
    /// of cookie theft via techniques like cross-site scripting.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sitetrace-axum::SiteTraceLayer;
    ///
    /// let service = SiteTraceLayer::new(session_store).with_http_only(true);
    /// ```
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Configures the `"SameSite"` attribute of the cookie used for the
    /// session.
    /// The default value is [`SameSite::Strict`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sitetrace-axum::SiteTraceLayer;
    /// use tower_sessions::{cookie::SameSite, MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_service = SessionManagerLayer::new(session_store).with_same_site(SameSite::Lax);
    /// ```
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Configures the `"Max-Age"` attribute of the cookie used for the session.
    /// The default value is `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use time::Duration;
    /// use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_expiry = Expiry::OnInactivity(Duration::hours(1));
    /// let session_service = SessionManagerLayer::new(session_store).with_expiry(session_expiry);
    /// ```
    pub fn with_expiry(mut self, expiry: Expiry) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Configures the `"Secure"` attribute of the cookie used for the session.
    /// The default value is `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_sessions::{MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_service = SessionManagerLayer::new(session_store).with_secure(true);
    /// ```
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Configures the `"Path"` attribute of the cookie used for the session.
    /// The default value is `"/"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_sessions::{MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_service = SessionManagerLayer::new(session_store).with_path("/some/path");
    /// ```
    pub fn with_path<P: Into<Cow<'static, str>>>(mut self, path: P) -> Self {
        self.path = path.into();
        self
    }

    /// Configures the `"Domain"` attribute of the cookie used for the session.
    /// The default value is `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tower_sessions::{MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_service = SessionManagerLayer::new(session_store).with_domain("localhost");
    /// ```
    pub fn with_domain<D: Into<Cow<'static, str>>>(
        mut self,
        domain: D,
    ) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Configures whether unmodified session should be saved on read or not.
    /// When the value is `true`, the session will be saved even if it was not
    /// changed.
    ///
    /// This is useful when you want to reset [`Session`] expiration time
    /// on any valid request at the cost of higher [`SessionStore`] write
    /// activity and transmitting `set-cookie` header with each response.
    ///
    /// It makes sense to use this setting with relative session expiration
    /// values, such as `Expiry::OnInactivity(Duration)`. This setting will
    /// _not_ cause session id to be cycled on save.
    ///
    /// The default value is `false`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use time::Duration;
    /// use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
    ///
    /// let session_store = MemoryStore::default();
    /// let session_expiry = Expiry::OnInactivity(Duration::hours(1));
    /// let session_service = SessionManagerLayer::new(session_store)
    ///     .with_expiry(session_expiry)
    ///     .with_always_save(true);
    /// ```
    pub fn with_always_save(mut self, always_save: bool) -> Self {
        self.always_save = always_save;
        self
    }

    pub(crate) fn expiry_date(&self) -> OffsetDateTime {
        match self.expiry {
            Some(Expiry::OnInactivity(duration)) => {
                OffsetDateTime::now_utc().saturating_add(duration)
            }
            Some(Expiry::AtDateTime(datetime)) => datetime,
            Some(Expiry::OnSessionEnd) | None => OffsetDateTime::now_utc()
                .saturating_add(DEFAULT_COOKIE_DURATION),
        }
    }
}

impl Default for CookieConfig<'static> {
    fn default() -> Self {
        CookieConfig {
            name: SITETRACE_COOKIE.into(),
            http_only: true,
            same_site: SameSite::Strict,
            expiry: None,
            secure: true,
            path: "/".into(),
            domain: None,
            always_save: false,
        }
    }
}
