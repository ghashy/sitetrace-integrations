use std::net::SocketAddr;

use axum::{
    extract::{connect_info::IntoMakeServiceWithConnectInfo, ConnectInfo},
    middleware::AddExtension,
    serve::Serve,
    Router,
};
use tokio::net::TcpListener;

#[allow(dead_code)]
type Server = Serve<
    IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
    AddExtension<Router, ConnectInfo<SocketAddr>>,
>;

#[allow(dead_code)]
pub struct App {
    pub server: Server,
}

#[allow(dead_code)]
impl App {
    pub async fn new(app: Router) -> Self {
        let address = format!("{}:{}", "127.0.0.1", 8001);
        let listener = TcpListener::bind(address).await.unwrap();

        Self {
            server: axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            ),
        }
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("failed to install signal handler")
        .recv()
        .await;
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("Terminate signal received");
}
