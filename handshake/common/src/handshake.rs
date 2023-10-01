
use tokio_socks::tcp::Socks5Stream;
use tokio::io::{AsyncRead, AsyncWrite};
pub trait HandshakeStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl HandshakeStream for Socks5Stream<tokio::net::TcpStream> {}
