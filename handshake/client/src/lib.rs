// This is a demo of an encrypted connection over TCP using Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s
// Some simplifications have been made
// 1. The server address is hardcoded
// 2. The proxy address is hardcoded
// 3. The proxy username and password are hardcoded
// 4. There is only one protocol Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s
//
// The protocol itself is manually implemented, however curve25519 ChaChaPoly1305 and BLAKE2s
// are implemented using the RustCrypto libraries.
//
// The two nodes exchange their peer ids as proof of concept,
// and print them to the console.
// The use of the swarm key is simulated by hardcoding it.
// The handshake is initiated by a plugin but there is currently no
// direct communication after the handshake.
//
// The file descriptor of the encrypted stream is provided but not used.
use common::errors::HandshakeError;
use common::noise::{
    decode_shared_secret, diffie_hellman, generate_keypair, mix_keys, EncryptedTcpStream,
};

use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::TargetAddr;

const LOOP_DELAY: u64 = 1000;

/// Represents a result for FFI with either data or an error.
///
/// - `data`: Success outcome, null if error is present.
/// - `error`: Error message, null if data is present.
///
/// Consumers MUST free the allocated memory for `data` and `error`.
#[repr(C)]
pub struct FFIResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

struct ServerState {
    runtime: tokio::runtime::Runtime,
    shutdown_signal: Option<oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<Result<String, HandshakeError>>>,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Option<ServerState>> = Mutex::new(None);
}

fn convert_rust_result_to_ffi_result(
    res: std::result::Result<String, HandshakeError>,
) -> *mut FFIResult {
    match res {
        Ok(data) => {
            let data_cstr = match CString::new(data) {
                Ok(cstr) => cstr,
                Err(_) => CString::new("Invalid string with null byte")
                    .expect("Static string should not fail"),
            };
            Box::into_raw(Box::new(FFIResult {
                data: data_cstr.into_raw(),
                error: std::ptr::null_mut(),
            }))
        }
        Err(e) => {
            let error_cstr = match CString::new(e.to_string()) {
                Ok(cstr) => cstr,
                Err(_) => CString::new("Error converting to CString")
                    .expect("Static string should not fail"),
            };
            Box::into_raw(Box::new(FFIResult {
                data: std::ptr::null_mut(),
                error: error_cstr.into_raw(),
            }))
        }
    }
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

fn start_rust_client(peer_id: &str) -> std::result::Result<String, HandshakeError> {
    let pid = format!("Initiator peer id: {}", peer_id);
    println!("Hello, I am {}", pid);
    let swarm_key = "/key/swarm/psk/1.0.0/
/base16/
b014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351
";
    // Create a shutdown signal
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()?;

    let mut buf = vec![0u8; 65535];

    let proxy_addr: SocketAddr = "172.19.0.3:1080".parse().expect("Invalid proxy address");
    let server_addr: SocketAddr = "172.18.0.2:2000".parse().expect("Invalid server address");
    let target = TargetAddr::Ip(server_addr);

    // Connect to the server via a socks proxy
    let server_handle = Some(rt.spawn(async move {
        let mut stream =
            Socks5Stream::connect_with_password(proxy_addr, target, "socks", "socks").await?;
        println!(
            "Now connected to server {} via socks proxy at {}",
            server_addr, proxy_addr
        );

        // Generate a new keypair
        let key_pair = generate_keypair()?;

        // -> e
        stream.write_all(key_pair.public.as_ref()).await?;

        // <- e
        let len = stream.read_exact(&mut buf[..key_pair.public.len()]).await?;
        let server_ephemeral = &buf[..len];

        // ee
        let shared_secret = generate_shared_secret(server_ephemeral, key_pair, swarm_key)?;

        // Upgrade the stream to an encrypted stream using our shared secret for encryption
        let mut encrypted_stream = EncryptedTcpStream::upgrade(stream, shared_secret);

        // Experimental and unfinished feature
        // Get the raw file descriptor of the encrypted stream
        // for possible handover to another process
        let _fd = encrypted_stream.as_raw_fd();

        // We now loop until we receive a shutdown signal
        loop {
            // Check for shutdown signal inside your main loop:
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv()
            {
                println!("Received shutdown signal");
                return Ok::<_, HandshakeError>("Client shutting down".into());
            }

            // Now all we have to do is read and write to the encrypted stream
            // The encrypted stream will encrypt and decrypt the data for us
            encrypted_stream.send(pid.as_bytes()).await?;
            println!("Client sent: {}", pid);

            let msg = encrypted_stream.recv().await?;
            println!("Server answered : {}", String::from_utf8_lossy(&msg));

            println!("Client sleeping for {LOOP_DELAY} milliseconds");
            tokio::time::sleep(tokio::time::Duration::from_millis(LOOP_DELAY)).await;
        }
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

// This function is used to generate a shared secret from the server ephemeral
// and the client's private key. This could be shortened but is left
// in this form for clarity.
// Note the absense of a one-time key (OTK) in this example.
// The OTK is not used because we are using NN which does not authenticate.
// This makes this protocol vulnerable to replay attacks.
fn generate_shared_secret(
    server_ephemeral: &[u8],
    key_pair: common::noise::Keypair,
    swarm_key: &str,
) -> Result<Vec<u8>, HandshakeError> {
    let private_key = key_pair.private.as_slice();
    let ristretto_point = diffie_hellman(private_key, server_ephemeral)?;
    let dh_secret = ristretto_point.compress().to_bytes();
    let pre_shared_key = decode_shared_secret(swarm_key)?;
    let shared_secret = mix_keys(&dh_secret, &pre_shared_key);
    Ok(shared_secret)
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
