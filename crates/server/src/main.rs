//! Composition root: the only place where concrete implementations are chosen.

use std::{env, net::SocketAddr};

use passguardian_server_data::NoopStorage;
use passguardian_server_domain::HealthService;
use tokio::{net::TcpListener, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_BIND: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind: SocketAddr = env::var("PASSGUARDIAN_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.into())
        .parse()?;

    let app = passguardian_server_api::router(HealthService::new(NoopStorage));

    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!("server stopped");
    Ok(())
}

async fn shutdown_signal() {
    // If the handler cannot be installed we stop anyway: better than ignoring SIGINT.
    let _ = signal::ctrl_c().await;
}
