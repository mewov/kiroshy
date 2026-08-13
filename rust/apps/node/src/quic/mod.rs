use std::{net::SocketAddr, time::Duration};
use anyhow::Result;
use quinn::{Connection, ServerConfig};

pub mod config;

#[tracing::instrument(skip(config, addr, write_timeout, read_timeout))]
pub async fn listen(config: ServerConfig, addr: SocketAddr, write_timeout: Duration, read_timeout: Duration) -> Result<()> {
    let endpoint = quinn::Endpoint::server(config, addr)?;
    tracing::info!(%addr, "start");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let addr = conn.remote_address();
                    crate::quic::connection(conn, addr).await
                },
                Err(err) => tracing::error!(%err, "accept connection"), 
            }
        });
    }

    Ok(())
}

#[tracing::instrument(skip(connection))]
pub async fn connection(connection: Connection, addr: SocketAddr) {
    tracing::info!("accept connection")
    // ...
}