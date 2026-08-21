use anyhow::{Context, Result};
use quinn::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::sync::Arc;

use crate::quic::NODE_PROTO;

#[derive(Debug)]
struct SkipClientVerification;

impl ClientCertVerifier for SkipClientVerification {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(&self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

pub fn create_server_config(cert_chain: Vec<CertificateDer<'static>>, key_der: PrivateKeyDer<'static>) -> Result<ServerConfig> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(SkipClientVerification)) // Прямо так, без .dangerous()
        .with_single_cert(cert_chain, key_der)
        .context("invalid cert or key for tls")?;

    tls_config.alpn_protocols = vec![NODE_PROTO.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).context("failed to convert tls config to quic config")?;

    Ok(ServerConfig::with_crypto(Arc::new(quic_crypto)))
}
