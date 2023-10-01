/// This code works but is intentionally left in an earlier development stage
/// to show the evolution of the code.
/// It is functional, but is missing production modifications like full error handling
/// abstractions for testing and refactoring.
use common::errors::HandshakeError;
use common::noise::{
    decode_shared_secret, diffie_hellman, generate_keypair, mix_keys, EncryptedTcpStream,
};
use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

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

fn convert_to_ffi_result(res: Result<String, HandshakeError>) -> *mut FFIResult {
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
pub unsafe extern "C" fn start_server(peer_id: *const c_char) -> *mut FFIResult {
    let peer_id = match CStr::from_ptr(peer_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            return Box::into_raw(Box::new(FFIResult {
                data: std::ptr::null_mut(),
                error: CString::new("Invalid peer id format").unwrap().into_raw(),
            }))
        }
    };
    let result = start_rust_server(peer_id);
    convert_to_ffi_result(result)
}

fn start_rust_server(peer_id: &str) -> Result<String, HandshakeError> {
    let pid = Arc::new(format!("Listener peer id: {}", peer_id));
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

    let server_handle = Some(rt.spawn(async move {
        // Bind to listener address and port
        let listener = TcpListener::bind("172.18.0.2:2000").await?;
        println!("Listening on: {}", listener.local_addr().unwrap());

        // Await a connection and read the message
        let (mut stream, addr) = listener.accept().await?;
        println!("Got connection from: {:?}", addr);

        // Generate a new keypair
        let key_pair = generate_keypair()?;
        println!("Server generated keypair {:?}", key_pair);
        // <- e
        let len = stream.read_exact(&mut buf[..key_pair.public.len()]).await?;
        println!("Server received something");
        let client_ephemeral = &buf[..len];
        println!("Server received {} bytes", len);
        println!("Server received {:?}", client_ephemeral);

        // -> e, ee
        stream.write_all(key_pair.public.as_ref()).await?;
        println!("Server sent ephemeral public key to client");
        let private_key = key_pair.private.as_slice();
        let ristretto_point = diffie_hellman(private_key, client_ephemeral)?;
        let dh_secret = ristretto_point.compress().to_bytes();
        let psk = decode_shared_secret(swarm_key)?;
        let shared_secret = mix_keys(&dh_secret, &psk);
        println!("Shared secret: {:?}", shared_secret);
        let mut encrypted_stream = EncryptedTcpStream::upgrade(stream, shared_secret);
        println!("Server side session established...");

        let mut n = 0u32;

        loop {
            n += 1;
            println!("Server loop iteration: {}", n);
            // Check for shutdown signal inside your main loop:
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv()
            {
                println!("Received shutdown signal");
                return Ok::<_, HandshakeError>("Server shutting down".into());
            }
            // Clone the arc to pass it to the spawned task
            let pid = Arc::clone(&pid);

            let msg = encrypted_stream.recv().await?;
            // let msg = recv(&mut stream).await?;

            println!("Client sent message : {}", String::from_utf8_lossy(&msg));
            // Answer with your own peer id
            encrypted_stream.send(pid.as_bytes()).await?;
            println!("Server answered with its peer id : {}", pid);

            println!("Server sleeping for 1000 milliseconds");
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
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
