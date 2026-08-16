use crate::packets::types::{IDENTITY_LENGTH, MAX_PAYLOAD_LENGTH, Packet, PacketKind};
use anyhow::{Context, Result, bail};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub mod types;

pub struct Frame<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> {
    w: W,
    r: R,
    write_timeout: Duration,
    read_timeout: Duration,
}

impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> Frame<W, R> {
    pub fn new(w: W, r: R, write_timeout: Duration, read_timeout: Duration) -> Self {
        Self {
            w,
            r,
            write_timeout,
            read_timeout,
        }
    }

    pub async fn send(&mut self, p: &Packet) -> Result<()> {
        let length = p.payload.len();
        if length > MAX_PAYLOAD_LENGTH {
            bail!("payload is too large");
        }

        let payload_len_u32 = u32::try_from(length)?;

        let mut buffer = Vec::with_capacity(1 + IDENTITY_LENGTH + 4 + length);

        buffer.push(p.kind as u8);
        buffer.extend_from_slice(&p.identity);
        buffer.extend_from_slice(&payload_len_u32.to_be_bytes());
        buffer.extend_from_slice(&p.payload);

        timeout(self.write_timeout, self.w.write_all(&buffer)).await??;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Packet> {
        let mut header = [0u8; 1 + IDENTITY_LENGTH + 4];
        timeout(self.read_timeout, self.r.read_exact(&mut header)).await??;

        let kind = PacketKind::try_from(header[0]).context("invalid packet kind")?;
        let identity: [u8; 32] = header[1..1 + IDENTITY_LENGTH].try_into()?;
        let length = u32::from_be_bytes(header[1 + IDENTITY_LENGTH..1 + IDENTITY_LENGTH + 4].try_into()?) as usize;

        if length > MAX_PAYLOAD_LENGTH {
            bail!("payload is too large");
        }

        let mut payload = vec![0u8; length];
        timeout(self.read_timeout, self.r.read_exact(&mut payload)).await??;

        Ok(Packet { kind, identity, payload })
    }
}
