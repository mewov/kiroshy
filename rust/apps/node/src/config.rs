use anyhow::{Context, Result};
use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub write_timeout: Duration,
    pub read_timeout: Duration,
    pub pem_path: PathBuf,
    pub key_path: PathBuf,
    pub identity_path: PathBuf,
}

impl Config {
    pub fn from_environment() -> Result<Self> {
        let addr: SocketAddr = env::var("NODE_ADDR").context("failed find $NODE_ADDR")?.parse().context("$NODE_ADDR is not ip address")?;

        let write_timeout: u64 = env::var("NODE_WRITE_TIMEOUT")
            .context("failed find $NODE_WRITE_TIMEOUT")?
            .parse()
            .context("$NODE_WRITE_TIMEOUT is not u64")?;
        let read_timeout: u64 = env::var("NODE_READ_TIMEOUT")
            .context("failed find $NODE_READ_TIMEOUT")?
            .parse()
            .context("$NODE_READ_TIMEOUT is not u64")?;

        let write_timeout = Duration::from_secs(write_timeout);
        let read_timeout = Duration::from_secs(read_timeout);

        let pem_path: PathBuf = env::var("NODE_PEM_PATH")
            .context("failed find $NODE_PEM_PATH")?
            .parse()
            .context("failed convert $NODE_PEM_PATH to PathBuf")?;
        let key_path: PathBuf = env::var("NODE_KEY_PATH")
            .context("failed find $NODE_KEY_PATH")?
            .parse()
            .context("failed convert $NODE_KEY_PATH to PathBuf")?;
        let identity_path: PathBuf = env::var("NODE_IDENTITY_PATH")
            .context("failed find $NODE_IDENTITY_PATH")?
            .parse()
            .context("failed convert $NODE_IDENTITY_PATH to PathBuf")?;

        Ok(Self {
            addr,
            write_timeout,
            read_timeout,
            pem_path,
            key_path,
            identity_path,
        })
    }
}
