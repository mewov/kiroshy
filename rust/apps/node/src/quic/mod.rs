use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use quinn::{Connection, ServerConfig};
use std::{net::SocketAddr, sync::Arc, time::Duration};

pub mod config;
mod peer;

const VERSION: (u8, u8, u8) = (0, 1, 0);

#[tracing::instrument(skip(config, addr, write_timeout, read_timeout))]
pub async fn listen(config: ServerConfig, addr: SocketAddr, signing: SigningKey, write_timeout: Duration, read_timeout: Duration) -> Result<()> {
    let endpoint = quinn::Endpoint::server(config, addr)?;
    tracing::info!(%addr, "start");

    let signing = Arc::new(signing);
    while let Some(incoming) = endpoint.accept().await {
        let signing = Arc::clone(&signing);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(err) = crate::quic::connection(conn, write_timeout, read_timeout, &signing).await {
                        tracing::error!(%err, "connection")
                    }
                }
                Err(err) => tracing::error!(%err, "accept connection"),
            };
        });
    }

    Ok(())
}

#[tracing::instrument(skip_all)]
pub async fn connection(connection: Connection, write_timeout: Duration, read_timeout: Duration, signing: &SigningKey) -> Result<()> {
    let (mut w, mut r) = connection.accept_bi().await?;
    let (step, version) = proto::handshake::frame_node::initial(&mut r, read_timeout).await?;

    anyhow::ensure!(version.0 == VERSION.0, "version mismatch");

    let peer = peer::get_peer_cert_bytes(&connection).context("failed get peer identity")?;
    step.verify(&mut w, &peer, write_timeout, signing, VERSION).await?;

    // ...
    Ok(())
}
