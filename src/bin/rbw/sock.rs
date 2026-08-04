use std::io::{BufRead as _, Write as _};

use anyhow::Context as _;

pub struct Sock(std::io::BufReader<std::os::unix::net::UnixStream>);

impl Sock {
    // not returning anyhow::Result here because we want to be able to handle
    // specific kinds of std::io::Results differently
    pub fn connect() -> std::io::Result<Self> {
        Ok(Self(std::io::BufReader::new(
            std::os::unix::net::UnixStream::connect(rbw::dirs::socket_file())?,
        )))
    }

    pub fn send(
        &mut self,
        msg: &rbw::protocol::Request,
    ) -> anyhow::Result<()> {
        let Self(sock) = self;
        sock.get_mut()
            .write_all(
                serde_json::to_string(msg)
                    .context("failed to serialize message to agent")?
                    .as_bytes(),
            )
            .context("failed to send message to agent")?;
        sock.get_mut()
            .write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> anyhow::Result<rbw::protocol::Response> {
        let Self(sock) = self;
        let mut line = String::new();
        sock.read_line(&mut line)
            .context("failed to read message from agent")?;
        serde_json::from_str(&line)
            .context("failed to parse message from agent")
    }
}
