use common::errors::HandshakeError;
use common::handshake::HandshakeStream;
use common::noise::{generate_keypair, EncryptedTcpStream};
use common::{
    convert_rust_result_to_ffi_result, generate_shared_secret, FFIResult, SERVER_ADDR, SWARM_KEY,
};
use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

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
pub unsafe extern "C" fn start_server(peer_id: *const c_char) -> *mut FFIResult {
    let peer_id = match CStr::from_ptr(peer_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            return Box::into_raw(Box::new(FFIResult {
                data: std::ptr::null_mut(),
                error: CString::new("Invalid peer id format")
                    .expect("Failed to create CString")
                    .into_raw(),
            }));
        }
    };
    let result = start_rust_server(peer_id);
    convert_rust_result_to_ffi_result(result)
}

// Rust entry point free of any FFI ))
fn start_rust_server(peer_id: &str) -> Result<String, HandshakeError> {
    let pid = format!("Listener peer id: {}", peer_id);
    println!("Hello, I am {}", pid);

    // Create a shutdown signal
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()?;

    // Listen to the client
    let server_handle = Some(rt.spawn(async move {
        let stream = listen_to_client().await?;
        let encrypted_stream = perform_server_handshake(stream).await?;
        handle_server_communication(encrypted_stream, &pid, shutdown_receiver).await
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
    Ok("Listener runtime sucessfully started".into())
}

/// Shuts down the active server instance.
///
/// This function sends a shutdown signal to the server task, waits for it to
/// finish its operations, and releases its resources.
#[no_mangle]
pub extern "C" fn close_server() {
    let mut server_state = SERVER_STATE.lock().unwrap();

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

async fn handle_server_communication<T: HandshakeStream>(
    mut encrypted_stream: EncryptedTcpStream<T>,
    pid: &str,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) -> Result<String, HandshakeError> {
    let mut counter = 0u32;
    loop {
        // Check for shutdown signal inside your main loop:
        if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv() {
            println!("Received shutdown signal");
            return Ok::<_, HandshakeError>("Server shutting down".into());
        }

        let msg = encrypted_stream.recv().await?;
        println!("Client sent: {}", String::from_utf8_lossy(&msg));

        // Answer with your own peer id
        encrypted_stream.send(pid.as_bytes()).await?;
        println!("Server answered: {}", pid);

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        counter += 1;
        println!("Server loop iteration: {}", counter);
    }
}

async fn perform_server_handshake<S: HandshakeStream>(
    mut stream: S,
) -> Result<EncryptedTcpStream<S>, HandshakeError> {
    let mut buf = vec![0u8; 65535];

    // Generate a new keypair
    let key_pair = generate_keypair()?;

    // <- e
    let len = stream.read_exact(&mut buf[..key_pair.public.len()]).await?;
    let client_ephemeral = &buf[..len];

    // -> e
    stream.write_all(key_pair.public.as_ref()).await?;
    println!("Server sent ephemeral public key to client");

    // ee
    let shared_secret = generate_shared_secret(client_ephemeral, key_pair, SWARM_KEY)?;

    Ok(EncryptedTcpStream::upgrade(stream, shared_secret))
}

async fn listen_to_client() -> Result<TcpStream, HandshakeError> {
    let listener = TcpListener::bind(SERVER_ADDR).await?;
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use common::mock::ServerMockStream;

    #[cfg(test)]
    async fn accept_from_client() -> Result<ServerMockStream, HandshakeError> {
        // Simulate a client connecting to the server
        let socket_addr = SERVER_ADDR.parse().unwrap();
        ServerMockStream::accept(socket_addr)
    }

    #[tokio::test]
    async fn test_accept_from_client() {
        let result: Result<ServerMockStream, HandshakeError> = accept_from_client().await;
        assert!(result.is_ok());

        let mock_stream = result.unwrap();

        assert_eq!(mock_stream.recv_data.len(), 0);
        assert_eq!(
            mock_stream.server_addr,
            Some(SERVER_ADDR.parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_unencrypted_pid_exchange() {
        let mut mock_stream = ServerMockStream::default();

        let mut receive_buffer = vec![0; 32];

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
        let mut mock_stream = ServerMockStream::default();

        // Set expected reply for when the client sends its public key.
        // This is a simulated ephemeral key from the server.
        mock_stream.set_reply(vec![2; 32]); // just an example value

        // Execute the handshake
        let result = perform_server_handshake(mock_stream).await;

        // Verify
        assert!(result.is_ok(), "Handshake should be successful");

        // Further assertions can be made based on expected states or behaviors,
        // such as checking if the correct shared secret was generated.
    }

}
