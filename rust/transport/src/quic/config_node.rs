use crate::quic::NODE_PROTO;
use anyhow::{Context, Result};
use quinn::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

pub fn create_server_config(cert_chain: Vec<CertificateDer<'static>>, key_der: PrivateKeyDer<'static>) -> Result<ServerConfig> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .context("invalid cert or key for tls")?;

    tls_config.alpn_protocols = vec![NODE_PROTO.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).context("failed to convert tls config to quic config")?;

    Ok(ServerConfig::with_crypto(Arc::new(quic_crypto)))
}
