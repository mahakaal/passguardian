//! Composition root: the only place where concrete implementations are chosen.
//!
//! Configuration (environment):
//! - `DATABASE_URL` (required): the PostgreSQL database; pending migrations are applied at start.
//! - `PASSGUARDIAN_BIND`: address to listen on (default `127.0.0.1:8080`).
//! - `PASSGUARDIAN_TOKEN_SECRET`: base64 of at least 32 random bytes that signs the tokens.
//!   If missing, a random one is generated and every restart logs everybody out.

mod system;

use std::{env, net::SocketAddr};

use base64::{engine::general_purpose::STANDARD, Engine};
use passguardian_server_api::{router, tokens::TokenSigner, AppState};
use passguardian_server_data::PgStore;
use tokio::{net::TcpListener, signal};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::system::{RandomIds, SystemClock};

const DEFAULT_BIND: &str = "127.0.0.1:8080";

fn token_signer() -> Result<TokenSigner, Box<dyn std::error::Error>> {
    if let Ok(encoded) = env::var("PASSGUARDIAN_TOKEN_SECRET") {
        let secret = STANDARD.decode(encoded.trim())?;
        return Ok(TokenSigner::new(&secret)?);
    }
    warn!("PASSGUARDIAN_TOKEN_SECRET is not set: using a random secret, sessions end at restart");
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|_| "the operating system gave no random bytes")?;
    Ok(TokenSigner::new(&secret)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind: SocketAddr = env::var("PASSGUARDIAN_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.into())
        .parse()?;
    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required (a PostgreSQL URL)")?;

    let store = PgStore::connect(&database_url).await?;
    store.migrate().await?;
    info!("database ready, migrations applied");

    let app = router(AppState::new(
        store,
        SystemClock,
        RandomIds,
        token_signer()?,
    ));

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
