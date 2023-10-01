use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{errors::HandshakeError, handshake::HandshakeStream, noise::EncryptedTcpStream};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_socks::{tcp::Socks5Stream, TargetAddr};

use async_trait::async_trait;

pub trait Acceptable {
    fn accept(
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, HandshakeError>>>>;
    type Output;
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

#[derive(Debug, Default)]
pub struct ClientMockStream {
    pub sent_data: Vec<u8>,
    pub recv_data: Vec<u8>,
    pub proxy_addr: Option<SocketAddr>,
    pub target: Option<TargetAddr<'static>>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Default)]
pub struct ServerMockStream {
    pub sent_data: Vec<u8>,
    pub recv_data: Vec<u8>,
    pub server_addr: Option<SocketAddr>,
}

impl ServerMockStream {
    pub fn new(recv_data: Vec<u8>) -> Self {
        Self {
            sent_data: Vec::new(),
            recv_data,
            server_addr: None,
        }
    }

    pub fn accept(
        server_addr: SocketAddr,
    ) -> Result<Self, HandshakeError> {
        let mut stream = ServerMockStream::new(vec![]);
        stream.server_addr = Some(server_addr);
        Ok(stream)
    }

    pub fn set_reply(&mut self, data: Vec<u8>) {
        self.recv_data = data;
    }
}

impl ClientMockStream {
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
        let mut stream = ClientMockStream::new(vec![]);
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

impl HandshakeStream for ClientMockStream {}
impl HandshakeStream for ServerMockStream {}

impl AsyncRead for ClientMockStream {
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

impl AsyncWrite for ClientMockStream {
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

impl AsyncRead for ServerMockStream {
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

impl AsyncWrite for ServerMockStream {
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
impl Connectable for ClientMockStream {
    async fn connect_with_password<'a>(
        proxy_addr: SocketAddr,
        target: TargetAddr<'a>,
        username: &'a str,
        password: &'a str,
    ) -> Result<Self, HandshakeError> {
        let mut stream = ClientMockStream::new(vec![]);
        stream.proxy_addr = Some(proxy_addr);
        stream.target = Some(target.to_owned());
        stream.username = Some(username.to_string());
        stream.password = Some(password.to_string());

        Ok(stream)
    }
}

impl EncryptedTcpStream<ClientMockStream> {
    pub fn set_reply(&mut self, data: Vec<u8>) {
        self.inner.recv_data = data;
    }
}

impl EncryptedTcpStream<ServerMockStream> {
    pub fn set_reply(&mut self, data: Vec<u8>) {
        self.inner.recv_data = data;
    }
}

impl Acceptable for ServerMockStream {
    fn accept(
        _addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, HandshakeError>>>> {
        Box::pin(async move {
            let stream = ServerMockStream::default();
            Ok(stream)
        })
    }
    type Output = ServerMockStream;
}

impl Acceptable for TcpListener {
    type Output = TcpStream;

    fn accept(
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, HandshakeError>>>> {
        Box::pin(async move {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(HandshakeError::from)?;
            let (stream, _) = listener.accept().await.map_err(HandshakeError::from)?;
            Ok(stream)
        })
    }
}

#[async_trait]
impl Connectable for Socks5Stream<TcpStream> {
    async fn connect_with_password<'a>(
        proxy_addr: SocketAddr,
        target: TargetAddr<'a>,
        username: &'a str,
        password: &'a str,
    ) -> Result<Self, HandshakeError> {
        let target_addr = target.to_owned();
        let username = username.to_owned();
        let password = password.to_owned();

        Socks5Stream::connect_with_password(proxy_addr, target_addr, &username, &password)
            .await
            .map_err(HandshakeError::from)
    }
}
