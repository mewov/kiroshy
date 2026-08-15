use std::{net::SocketAddr, sync::Arc, time::Duration};
use anyhow::Result;
use ed25519_dalek::SigningKey;
use quinn::{Connection, ServerConfig};

pub mod config;

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
                    let addr = conn.remote_address();
                    if let Err(err) = crate::quic::connection(conn, write_timeout, read_timeout, &signing, addr).await {
                        tracing::error!(%err, %addr, "connection")
                    }
                },
                Err(err) => tracing::error!(%err, "accept connection"), 
            };
        });
    }

    Ok(())
}

#[tracing::instrument(skip_all, fields(%addr))]
pub async fn connection(connection: Connection, write_timeout: Duration, read_timeout: Duration, signing: &SigningKey, addr: SocketAddr) -> Result<()> {
    tracing::info!("accept connection");

    tracing::info!("accept bi");
    let (mut w, mut r) = connection.accept_bi().await?;

    tracing::info!("initial handshake");
    let (step, version) = proto::handshake::frame_node::initial(&mut r, read_timeout).await?;

    anyhow::ensure!(
        version.0 == VERSION.0,
        "version mismatch"
    );

    tracing::info!("confirm identity handshake");
    step.verify(&mut w, write_timeout, signing, VERSION).await?;

    tracing::info!("success handshake");

    // ...
    Ok(())
}