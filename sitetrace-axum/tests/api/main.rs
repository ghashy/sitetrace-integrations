use axum::{extract::FromRequestParts, routing, Router};

use sitetrace_axum::{SiteTraceExt, SiteTraceLayer};

use helpers::{shutdown_signal, App};
use time::Duration;
use tracing::Level;
mod helpers;

#[tokio::test]
async fn testme() {
    init_tracing();
    let session_store = tower_sessions::MemoryStore::default();
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_expiry(tower_sessions::Expiry::OnInactivity(Duration::days(1)));
    let layer: SiteTraceLayer<()> =
        SiteTraceLayer::new("apikey".to_owned(), |fut| {
            tokio::spawn(async move {
                match fut.await {
                    Ok(r) => {
                        dbg!(r);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to send request to sitetrace: {e}"
                        );
                    }
                }
            });
        });
    let app: Router<()> = Router::new()
        .route(
            "/hello",
            routing::get(
                |ext: SiteTraceExt,
                 session: tower_sessions::Session,
                 cookies: tower_cookies::Cookies| async move {
                    "Hello world"
                },
            ),
        )
        .layer(session_layer)
        .layer(layer);

    let app = App::new(app).await;
    app.server
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

fn init_tracing() {
    use tracing_subscriber::fmt::format::FmtSpan;
    if std::env::var("TEST_TRACING").is_ok() {
        let subscriber = tracing_subscriber::fmt()
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::default())
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(Level::INFO.into())
                    .add_directive("tower_sessions_core=warn".parse().unwrap())
                    .add_directive("axum::rejection=trace".parse().unwrap())
                    .add_directive("aws_config=warn".parse().unwrap()),
            )
            .compact()
            .with_level(true)
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}
