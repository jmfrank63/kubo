use std::fmt;

pub type DynError = Box<dyn std::error::Error + Send + 'static>;

#[derive(Debug)]
pub struct HandshakeError(DynError);

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        HandshakeError(Box::new(err))
    }
}

impl From<tokio_socks::Error> for HandshakeError {
    fn from(err: tokio_socks::Error) -> Self {
        HandshakeError(Box::new(err))
    }
}

impl From<chacha20poly1305::Error> for HandshakeError {
    fn from(err: chacha20poly1305::Error) -> Self {
        HandshakeError(Box::new(err))
    }
}

impl From<tokio::time::error::Elapsed> for HandshakeError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        HandshakeError(Box::new(err))
    }
}

impl From<std::array::TryFromSliceError> for HandshakeError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        HandshakeError(Box::new(err))
    }
}

impl From<hex::FromHexError> for HandshakeError {
    fn from(err: hex::FromHexError) -> Self {
        HandshakeError(Box::new(err))
    }
}
