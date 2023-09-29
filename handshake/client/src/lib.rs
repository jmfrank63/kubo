use lazy_static::lazy_static;
use snow::params::NoiseParams;
use snow::Builder;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
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
    let pid = format!("Client peer id: {}", peer_id);
    println!("Client started with peer id: {}", pid);
    // Create a shutdown signal
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

    let mut buf = vec![0u8; 65535];

    // Initialize our initiator using a builder.
    let builder: Builder<'_> = Builder::new(PARAMS.clone());
    let key_pair = builder
        .generate_keypair()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    let mut noise = builder
        .local_private_key(key_pair.private.as_slice())
        .build_initiator()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

    let server_handle = Some(rt.spawn(async move {
        // Connect via SOCKS5 proxy
        let proxy: std::net::SocketAddr = "172.19.0.3:1080".parse().unwrap();
        let target = TargetAddr::Domain("172.18.0.2".into(), 2000);
        let mut stream = Socks5Stream::connect_with_password(proxy, target, "socks", "socks")
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        println!("Now connected to server");

        // -> e
        let len = noise
            .write_message(&[], &mut buf)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        send(&mut stream, &buf[..len]).await?;

        // <- e, ee
        noise
            .read_message(&recv(&mut stream).await?, &mut buf)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

        let mut noise = noise
            .into_transport_mode()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
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

            let len = noise
                .write_message(pid.as_bytes(), &mut buf)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
            send(&mut stream, &buf[..len]).await?;
            println!("Sent message: {}", pid);

            let msg = recv(&mut stream).await?;

            let len = noise
                .read_message(&msg, &mut buf)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
            println!(
                "Server sent answer : {}",
                String::from_utf8_lossy(&buf[..len])
            );

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
    Ok("Server started".into())
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

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
async fn recv(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error + Send>> {
    let mut msg_len_buf = [0u8; 2];
    stream
        .read_exact(&mut msg_len_buf)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream
        .read_exact(&mut msg[..])
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
async fn send(stream: &mut TcpStream, buf: &[u8]) -> Result<(), Box<dyn std::error::Error + Send>> {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    stream
        .write_all(&msg_len_buf)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
    stream
        .write_all(buf)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)
}
