use common::errors::DynError;
use common::noise::{generate_keypair, diffie_hellman, mix_keys, decode_shared_secret, EncryptedTcpStream};
// Connection vor TCP using Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s
// Some simplifications have been made
// 1. The server address is hardcoded
// 2. The proxy address is hardcoded
// 3. The proxy username and password are hardcoded
// 4. There is only one protocol Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s
use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::TargetAddr;

#[repr(C)]
pub struct FFIResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

struct ServerState {
    runtime: tokio::runtime::Runtime,
    shutdown_signal: Option<oneshot::Sender<()>>,
    server_handle:
        Option<tokio::task::JoinHandle<Result<String, Box<dyn std::error::Error + Send>>>>,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Option<ServerState>> = Mutex::new(None);
}

fn convert_to_ffi_result(
    res: std::result::Result<String, Box<dyn std::error::Error + Send>>,
) -> *mut FFIResult {
    match res {
        Ok(data) => Box::into_raw(Box::new(FFIResult {
            data: CString::new(data).unwrap().into_raw(),
            error: std::ptr::null_mut(),
        })),
        Err(e) => Box::into_raw(Box::new(FFIResult {
            data: std::ptr::null_mut(),
            error: CString::new(e.to_string()).unwrap().into_raw(),
        })),
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
                error: CString::new("Invalid peer id format").unwrap().into_raw(),
            }))
        }
    };
    let result = start_rust_client(peer_id);
    convert_to_ffi_result(result)
}

fn start_rust_client(
    peer_id: &str,
) -> std::result::Result<String, Box<dyn std::error::Error + Send>> {
    let pid = format!("Initiator peer id: {}", peer_id);
    println!("Hello, I am {}", pid);
    let swarm_key = "b014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351";
    // Create a shutdown signal
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

    let mut buf = vec![0u8; 65535];

    // Define the target address
    let proxy_addr: SocketAddr = "172.19.0.3:1080".parse().unwrap();
    let server_addr: SocketAddr = "172.18.0.2:2000".parse().unwrap();
    let target = TargetAddr::Ip(server_addr);

    let server_handle = Some(rt.spawn(async move {
        let mut stream = Socks5Stream::connect_with_password(proxy_addr, target, "socks", "socks")
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        println!(
            "Now connected to server {} via socks proxy at {}",
            server_addr, proxy_addr
        );

        // Generate a new keypair
        let key_pair = generate_keypair()?;
        // -> e
        stream.write_all(key_pair.public.as_ref()).await
            .map_err(|e| Box::new(e) as DynError)?;

        // <- e, ee
        let len = stream.read_exact(&mut buf[..key_pair.public.len()]).await
            .map_err(|e| Box::new(e) as DynError)?;
        let server_ephemeral = &buf[..len];

        let private_key = key_pair.private.as_slice();
        let ristretto_point = diffie_hellman(private_key, server_ephemeral)?;
        let dh_secret = ristretto_point.compress().to_bytes();
        let psk = decode_shared_secret(swarm_key)?;
        let shared_secret = mix_keys(&dh_secret, &psk);

        let mut encrypted_stream = EncryptedTcpStream::upgrade(stream, shared_secret);
        println!("Client side session established...");

        let mut n = 0u32;

        loop {
            n += 1;
            println!("Client loop iteration: {}", n);
            // Check for shutdown signal inside your main loop:
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv()
            {
                println!("Received shutdown signal");
                return Ok::<_, Box<dyn std::error::Error + Send>>("Client shutting down".into());
            }

            encrypted_stream.send(pid.as_bytes()).await?;
            println!("Initiator sent message to listener: {}", pid);

            let msg = encrypted_stream.recv().await?;
            println!("Server answered : {}", String::from_utf8_lossy(&msg));

            println!("Client sleeping for 100 milliseconds");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }));

    // Store the runtime, shutdown signal, and server handle in the global state
    {
        let mut server_state = SERVER_STATE.lock().unwrap();
        *server_state = Some(ServerState {
            runtime: rt,
            shutdown_signal: Some(shutdown_sender),
            server_handle,
        });
    }
    Ok("Initiator runtime sucessfully started".into())
}

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
