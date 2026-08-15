mod config;
mod identity;
mod quic;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("start node...");

    dotenvy::dotenv().ok();
    let config = config::Config::from_environment().unwrap_or_else(|err| {
        tracing::error!(%err, "configuration");
        std::process::exit(1);
    });
    tracing::info!("configuration");

    if let Some(p) = config.pem_path.parent() { let _ = std::fs::create_dir_all(p); }
    if let Some(p) = config.key_path.parent() { let _ = std::fs::create_dir_all(p); }

    rustls::crypto::ring::default_provider().install_default().unwrap_or_else(|err| {
        tracing::error!(?err, "rustls provider");
        std::process::exit(1);
    });

   let quic_config = quic::config::initial(config.pem_path, config.key_path).unwrap_or_else(|err| {
        tracing::error!(%err, "quic configuration");
        std::process::exit(1);
    });
    tracing::info!("quic configuration");

    let signing = identity::initial(&config.identity_path).unwrap_or_else(|err| {
        tracing::error!(%err, "identity configuration");
        std::process::exit(1);
    });

    match quic::listen(quic_config, config.addr, signing, config.write_timeout, config.read_timeout).await {
        Ok(_) => tracing::info!("quic shutdown"),
        Err(err) => tracing::error!(%err, "quic listener")
    }
}