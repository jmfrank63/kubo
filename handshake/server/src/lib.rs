#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
use common::errors::DynError;
use common::noise::{decode_shared_secret, diffie_hellman, generate_keypair, mix_keys};
use lazy_static::lazy_static;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[repr(C)]
pub struct FFIResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

struct ServerState {
    runtime: tokio::runtime::Runtime,
    shutdown_signal: Option<oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<Result<String, DynError>>>,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Option<ServerState>> = Mutex::new(None);
}

fn convert_to_ffi_result(res: Result<String, DynError>) -> *mut FFIResult {
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

fn start_rust_server(peer_id: &str) -> Result<String, DynError> {
    let pid = Arc::new(format!("Listener peer id: {}", peer_id));
    println!("Hello, I am {}", pid);
    let swarm_key = "b014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351";
    // Create a shutdown signal
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new().map_err(|e| Box::new(e) as DynError)?;

    let mut buf = vec![0u8; 65535];

    let server_handle = Some(rt.spawn(async move {
        // Bind to listener address and port
        let listener = TcpListener::bind("172.18.0.2:2000")
            .await
            .map_err(|e| Box::new(e) as DynError)?;
        println!("Listening on: {}", listener.local_addr().unwrap());

        // Await a connection and read the message
        let (mut stream, addr) = listener
            .accept()
            .await
            .map_err(|e| Box::new(e) as DynError)?;
        println!("Got connection from: {:?}", addr);

        // Generate a new keypair
        let key_pair = generate_keypair()?;
        // <- e
        let len = stream
            .read_exact(&mut buf[..key_pair.public.len()])
            .await
            .map_err(|e| Box::new(e) as DynError)?;
        let client_ephemeral = &buf[..len];
        println!("Received initiator's public key: {:?}", client_ephemeral);

        // -> e, ee
        stream
            .write_all(key_pair.public.as_ref())
            .await
            .map_err(|e| Box::new(e) as DynError)?;
        let private_key = key_pair.private.as_slice();
        let ristretto_point = diffie_hellman(private_key, client_ephemeral)?;
        let dh_secret = ristretto_point.compress().to_bytes();
        let psk = decode_shared_secret(swarm_key)?;
        let _shared_secret = mix_keys(&dh_secret, &psk);

        // let mut noise = noise
        //     .into_transport_mode()
        //     .map_err(|e| Box::new(e) as DynError)?;
        println!("Server side session established...");

        let mut n = 0u32;

        loop {
            n += 1;
            println!("Server loop iteration: {}", n);
            // Check for shutdown signal inside your main loop:
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv()
            {
                println!("Received shutdown signal");
                return Ok::<_, DynError>("Server shutting down".into());
            }
            // Clone the arc to pass it to the spawned task
            let pid = Arc::clone(&pid);

            // let msg = recv(&mut stream).await?;

            // let len = noise
            //     .read_message(&msg, &mut buf)
            //     .map_err(|e| Box::new(e) as DynError)?;
            // println!(
            //     "Client sent message : {}",
            //     String::from_utf8_lossy(&buf[..len])
            // );
            // Answer with your own peer id
            // let len = noise
            //     .write_message(pid.as_bytes(), &mut buf)
            //     .map_err(|e| Box::new(e) as DynError)?;
            // send(&mut stream, &buf[..len]).await?;
            println!("Server answered with its peer id : {}", pid);
            // let hex_string: String = buf[..len]
            //     .iter()
            //     .map(|byte| format!("{:02x}", byte))
            //     .collect();
            // println!("Encrypted message sent to initiator: {}", hex_string);

            println!("Server sleeping for 100 milliseconds");
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
    Ok("Listener runtime sucessfully started".into())
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

// /// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
// async fn recv(stream: &mut TcpStream) -> Result<Vec<u8>, DynError> {
//     let mut msg_len_buf = [0u8; 2];
//     stream
//         .read_exact(&mut msg_len_buf)
//         .await
//         .map_err(|e| Box::new(e) as DynError)?;
//     let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
//     let mut msg = vec![0u8; msg_len];
//     stream
//         .read_exact(&mut msg[..])
//         .await
//         .map_err(|e| Box::new(e) as DynError)?;
//     Ok(msg)
// }

// /// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
// async fn send(stream: &mut TcpStream, buf: &[u8]) -> Result<(), DynError> {
//     let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
//     stream
//         .write_all(&msg_len_buf)
//         .await
//         .map_err(|e| Box::new(e) as DynError)?;
//     stream
//         .write_all(buf)
//         .await
//         .map_err(|e| Box::new(e) as DynError)
// }
