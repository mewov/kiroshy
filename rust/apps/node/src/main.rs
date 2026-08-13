mod config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("start node...");

    dotenvy::dotenv().ok();
    let config = config::Config::from_environment().unwrap_or_else(|err| {
        tracing::error!(%err, "configuration");
        std::process::exit(1);
    });

    if let Some(p) = config.pem_path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if let Some(p) = config.key_path.parent() {
        let _ = std::fs::create_dir_all(p);
    }

    tracing::info!("configuration");
}