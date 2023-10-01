use common::errors::HandshakeError;
/// This is a demo of an encrypted connection over TCP using `Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s`.
///
/// Some simplifications have been made:
/// 1. The server address is hardcoded.
/// 2. The proxy address is hardcoded.
/// 3. The proxy username and password are hardcoded.
/// 4. There is only one protocol: `Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s`.
///
/// The protocol itself is manually implemented. However, `curve25519`, `ChaChaPoly1305`, and `BLAKE2s`
/// are implemented using the RustCrypto libraries.
///
/// The two nodes exchange their peer ids as a proof of concept and print them to the console.
/// The use of the swarm key is simulated by hardcoding it.
/// The handshake is initiated by a plugin, but there is currently no direct communication after the handshake.
///
/// The file descriptor of the encrypted stream is provided but not used.
/// use common::errors::HandshakeError;
///
use common::handshake::HandshakeStream;
use common::noise::{generate_keypair, EncryptedTcpStream};

use common::{
    convert_rust_result_to_ffi_result, generate_shared_secret, FFIResult, LOOP_DELAY, PROXY_ADDR,
    SERVER_ADDR, SWARM_KEY,
};

use futures::Future;
use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::pin::Pin;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::TargetAddr;

struct ServerState {
    runtime: tokio::runtime::Runtime,
    shutdown_signal: Option<oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<Result<String, HandshakeError>>>,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Option<ServerState>> = Mutex::new(None);
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and points to
/// a valid object of the appropriate type.
#[no_mangle]
pub unsafe extern "C" fn start_client(peer_id: *const c_char) -> *mut FFIResult {
    let peer_id = match CStr::from_ptr(peer_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            return Box::into_raw(Box::new(FFIResult {
                data: std::ptr::null_mut(),
                error: CString::new("Invalid peer id format")
                    .expect("Failed to create CString")
                    .into_raw(),
            }))
        }
    };
    let result = start_rust_client(peer_id);
    convert_rust_result_to_ffi_result(result)
}

/// Shuts down the active server instance.
///
/// This function sends a shutdown signal to the server task, waits for it to
/// finish its operations, and releases its resources.
#[no_mangle]
pub extern "C" fn close_server() {
    let server_state_result = SERVER_STATE.lock();
    match server_state_result {
        Ok(mut server_state) => {
            if let Some(state) = &mut *server_state {
                if let Some(shutdown_sender) = state.shutdown_signal.take() {
                    let _ = shutdown_sender.send(());
                }

                // Ensure the server task is completed
                if let Some(server_handle) = state.server_handle.take() {
                    let _ = state.runtime.block_on(server_handle);
                }
            }
        }
        Err(_) => {
            let error = HandshakeError::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Runtime mutex error",
            ));
            eprintln!("Error: {:?}", error);
        }
    }
}

trait Connectable: AsyncReadExt + AsyncWriteExt {
    fn connect_with_password(
        proxy_addr: SocketAddr,
        target: TargetAddr,
        username: &str,
        password: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self, HandshakeError>>>>
    where
        Self: Sized;
}

impl Connectable for Socks5Stream<tokio::net::TcpStream> {
    fn connect_with_password(
        proxy_addr: SocketAddr,
        target: TargetAddr,
        username: &str,
        password: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self, HandshakeError>>>> {
        let target_addr = target.to_owned();
        let username = username.to_owned();
        let password = password.to_owned();
        Box::pin(async move {
            Socks5Stream::connect_with_password(proxy_addr, target_addr, &username, &password)
                .await
                .map_err(HandshakeError::from)
        })
    }
}

async fn connect_to_server() -> Result<Socks5Stream<tokio::net::TcpStream>, HandshakeError> {
    let proxy_addr: SocketAddr = PROXY_ADDR.parse().expect("Invalid proxy address");
    let server_addr: SocketAddr = SERVER_ADDR.parse().expect("Invalid server address");
    let target = TargetAddr::Ip(server_addr);
    Socks5Stream::<TcpStream>::connect_with_password(proxy_addr, target, "socks", "socks")
        .await
        .map_err(HandshakeError::from)
}

async fn perform_handshake<S: HandshakeStream>(
    mut stream: S,
) -> Result<EncryptedTcpStream<S>, HandshakeError> {
    let mut buf = vec![0u8; 65535];

    // Generate a new keypair
    let key_pair = generate_keypair()?;

    // -> e
    stream.write_all(key_pair.public.as_ref()).await?;

    // <- e
    let len = stream.read_exact(&mut buf[..key_pair.public.len()]).await?;
    let server_ephemeral = &buf[..len];

    // ee
    let shared_secret = generate_shared_secret(server_ephemeral, key_pair, SWARM_KEY)?;

    // Upgrade the stream to an encrypted stream using our shared secret for encryption
    Ok(EncryptedTcpStream::upgrade(stream, shared_secret))
}

async fn handle_client_communication<T: HandshakeStream>(
    mut encrypted_stream: EncryptedTcpStream<T>,
    pid: String,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) -> Result<String, HandshakeError> {
    loop {
        // Check for shutdown signal inside your main loop:
        if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv() {
            println!("Received shutdown signal");
            return Ok("Client shutting down".into());
        }

        // Now all we have to do is read and write to the encrypted stream
        // The encrypted stream will encrypt and decrypt the data for us
        encrypted_stream.send(pid.as_bytes()).await?;
        println!("Client sent: {}", pid);

        let msg = encrypted_stream.recv().await?;
        println!("Server answered: {}", String::from_utf8_lossy(&msg));

        println!("Client sleeping for {} milliseconds", LOOP_DELAY);
        tokio::time::sleep(tokio::time::Duration::from_millis(LOOP_DELAY)).await;
    }
}

// We now have FFI out of the way and can focus on the Rust implementation.
fn start_rust_client(peer_id: &str) -> Result<String, HandshakeError> {
    let pid = format!("Initiator peer id: {}", peer_id);
    println!("Hello, I am {}", pid);
    // Create a shutdown signal
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()?;

    // Connect to the server via a socks proxy
    let server_handle = Some(rt.spawn(async move {
        let stream = connect_to_server().await?;
        println!(
            "Now connected to server {} via proxy {}",
            SERVER_ADDR, PROXY_ADDR
        );

        let encrypted_stream = perform_handshake(stream).await?;

        handle_client_communication(encrypted_stream, pid, shutdown_receiver).await
    }));

    // Store the runtime, shutdown signal, and server handle in a global state
    {
        let server_state_result = SERVER_STATE.lock();
        match server_state_result {
            Ok(mut server_state) => {
                *server_state = Some(ServerState {
                    runtime: rt,
                    shutdown_signal: Some(shutdown_sender),
                    server_handle,
                });
            }
            Err(_) => {
                return Err(HandshakeError::from(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Runtime mutex error",
                )));
            }
        }
    }
    Ok("Initiator runtime sucessfully started".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::mock::MockStream;

    #[cfg(test)]
    async fn connect_to_server() -> Result<MockStream, HandshakeError> {
        let proxy_addr: SocketAddr = PROXY_ADDR.parse().expect("Invalid proxy address");
        let server_addr: SocketAddr = SERVER_ADDR.parse().expect("Invalid server address");
        let target = TargetAddr::Ip(server_addr);
        MockStream::connect_with_password(proxy_addr, target, "socks", "socks")
    }

    #[tokio::test]
    async fn test_connect_to_server() {
        let result: Result<MockStream, HandshakeError> = connect_to_server().await; // Explicitly mention the type
        assert!(result.is_ok());

        let mock_stream = result.unwrap();

        assert_eq!(mock_stream.recv_data.len(), 0);
        assert_eq!(
            mock_stream.proxy_addr,
            Some("172.19.0.3:1080".parse().unwrap())
        );
        assert_eq!(
            mock_stream.target,
            Some(TargetAddr::Ip("172.18.0.2:2000".parse().unwrap()))
        );
        assert_eq!(mock_stream.username, Some("socks".to_string()));
        assert_eq!(mock_stream.password, Some("socks".to_string()));
    }

    #[tokio::test]
    async fn test_pid_exchange() {
        let mut mock_stream = MockStream::default();
        let mut receive_buffer = vec![0; 32];

        // Simultate reading without anything send
        let result = mock_stream.read_exact(&mut receive_buffer).await;

        match result {
            Ok(_) => {
                assert_eq!(receive_buffer, vec![0; 32]);
            }
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            }
        }

        // Simulate sending pid
        mock_stream.write_all(&[0; 32]).await.unwrap();
        mock_stream.set_reply(vec![1; 32]);

        // Try reading the reply
        mock_stream.read_exact(&mut receive_buffer).await.unwrap();

        assert_eq!(receive_buffer, vec![1; 32]);
    }

    #[tokio::test]
    async fn test_perform_handshake() {
        // Setup mock stream
        let mut mock_stream = MockStream::default();

        // Set expected reply for when the client sends its public key.
        // This is a simulated ephemeral key from the server.
        mock_stream.set_reply(vec![2; 32]); // just an example value

        // Execute the handshake
        let result = perform_handshake(mock_stream).await;

        // Verify
        assert!(result.is_ok(), "Handshake should be successful");

        // Further assertions can be made based on expected states or behaviors,
        // such as checking if the correct shared secret was generated.
    }
}
