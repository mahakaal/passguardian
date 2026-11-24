//! Composition root: the only place where concrete implementations are chosen.

use std::{env, net::SocketAddr};

use passguardian_server_data::{NoopStorage, PgStore};
use passguardian_server_domain::HealthService;
use tokio::{net::TcpListener, signal};
use tracing::{info, warn};
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

    // With DATABASE_URL the server uses PostgreSQL and applies the pending migrations at start.
    // Without it, it runs on a placeholder storage that is always "up": enough to try the
    // health endpoint, nothing more.
    let app = if let Ok(url) = env::var("DATABASE_URL") {
        let store = PgStore::connect(&url).await?;
        store.migrate().await?;
        info!("database ready, migrations applied");
        passguardian_server_api::router(HealthService::new(store))
    } else {
        warn!("DATABASE_URL is not set: running without a database");
        passguardian_server_api::router(HealthService::new(NoopStorage))
    };

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
