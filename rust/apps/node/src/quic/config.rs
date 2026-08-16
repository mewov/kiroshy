use anyhow::{Context, Result};
use quinn::ServerConfig;
use rcgen::generate_simple_self_signed;
use std::{fs::File, io::BufReader, path::PathBuf, sync::Arc};

pub fn initial(pem_path: PathBuf, key_path: PathBuf) -> Result<ServerConfig> {
    if !pem_path.exists() || !key_path.exists() {
        let signed = generate_simple_self_signed(vec!["node".to_string()])?;
        let cert_pem = signed.cert.pem();
        let key_pem = signed.key_pair.serialize_pem();

        std::fs::write(&pem_path, cert_pem).context("failed to write cert to file")?;
        std::fs::write(&key_path, key_pem).context("failed to write key to file")?;
    }

    load_server_config(&pem_path, &key_path)
}

fn load_server_config(pem_path: &PathBuf, key_path: &PathBuf) -> Result<ServerConfig> {
    let cert_file = File::open(pem_path).context("failed to open certificates file")?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificates")?;

    let key_file = File::open(key_path).context("failed to open private key file")?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("private key not found found"))?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid cert or key for tls")?;

    tls_config.alpn_protocols = vec![b"node-v1".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).context("failed to convert tls config to quic config")?;

    Ok(ServerConfig::with_crypto(Arc::new(quic_crypto)))
}
