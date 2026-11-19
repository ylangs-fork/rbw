use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::io::BufReader<tokio::net::UnixStream>);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(tokio::io::BufReader::new(s))
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        let sock = sock.get_mut();
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<Option<rbw::protocol::Request>> {
        let Self(sock) = self;
        let mut line = String::new();
        if sock
            .read_line(&mut line)
            .await
            .context("failed to read message from socket")? == 0
        {
            return Ok(None);
        }
        serde_json::from_str(&line)
            .map(Some)
            .context("failed to parse request")
    }
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}
