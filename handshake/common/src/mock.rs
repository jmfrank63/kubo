use std::{net::SocketAddr, pin::Pin, task::{Context, Poll}};

use crate::{handshake::HandshakeStream, errors::HandshakeError, noise::EncryptedTcpStream};
use tokio::io::{AsyncWrite, AsyncRead, self};
use tokio_socks::TargetAddr;

use async_trait::async_trait;


#[derive(Debug, Default)]
pub struct MockStream {
    pub sent_data: Vec<u8>,
    pub recv_data: Vec<u8>,
    pub proxy_addr: Option<SocketAddr>,
    pub target: Option<TargetAddr<'static>>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[async_trait]
pub trait Connectable: AsyncRead + AsyncWrite {
    async fn connect_with_password<'a>(
        proxy_addr: SocketAddr,
        target: TargetAddr<'a>,
        username: &'a str,
        password: &'a str,
    ) -> Result<Self, HandshakeError>
    where
        Self: Sized;
}

impl MockStream {
    pub fn new(recv_data: Vec<u8>) -> Self {
        Self {
            sent_data: Vec::new(),
            recv_data,
            proxy_addr: None,
            target: None,
            username: None,
            password: None,
        }
    }

    pub fn connect_with_password(
        proxy_addr: SocketAddr,
        target: TargetAddr,
        username: &str,
        password: &str,
    ) -> Result<Self, HandshakeError> {
        let mut stream = MockStream::new(vec![]);
        stream.proxy_addr = Some(proxy_addr);
        stream.target = Some(target.to_owned());
        stream.username = Some(username.to_string());
        stream.password = Some(password.to_string());

        Ok(stream)
    }

    pub fn set_reply(&mut self, data: Vec<u8>) {
        self.recv_data = data;
    }
}

impl HandshakeStream for MockStream {}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        let len = std::cmp::min(buf.remaining(), self.recv_data.len());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }

        buf.put_slice(&self.recv_data[..len]);
        self.recv_data.drain(..len); // remove the data that was "read"
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.sent_data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mock the flush operation
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Mock the shutdown operation
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Connectable for MockStream {
    async fn connect_with_password<'a>(
        proxy_addr: SocketAddr,
        target: TargetAddr<'a>,
        username: &'a str,
        password: &'a str,
    ) -> Result<Self, HandshakeError> {
        let mut stream = MockStream::new(vec![]);
        stream.proxy_addr = Some(proxy_addr);
        stream.target = Some(target.to_owned());
        stream.username = Some(username.to_string());
        stream.password = Some(password.to_string());

        Ok(stream)
    }
}

impl EncryptedTcpStream<MockStream> {
    pub fn set_reply(&mut self, data: Vec<u8>) {
        self.inner.recv_data = data;
    }
}
