use lazy_static::lazy_static;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

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

#[no_mangle]
pub extern "C" fn start_server() -> *mut FFIResult {
    let result = start_rust_server();
    convert_to_ffi_result(result)
}

fn start_rust_server() -> std::result::Result<String, Box<dyn std::error::Error + Send>> {
    // Create a shutdown signal
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

    // Create the tokio runtime
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

    // Create an asynchronous channel
    let (tx, mut rx) = mpsc::channel(32);

    let server_handle = Some(rt.spawn(async move {
        // Bind to port 2000
        let listener = TcpListener::bind("172.18.0.2:2000")
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        println!("Listening on: {}", listener.local_addr().unwrap());

        loop {
            // Check for shutdown signal inside your main loop:
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = shutdown_receiver.try_recv()
            {
                println!("Received shutdown signal");
                return Ok::<_, Box<dyn std::error::Error + Send>>("Server shutting down".into());
            }

            // Await a connection and read the message
            let (mut socket, addr) = listener
                .accept()
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
            println!("Got connection from: {:?}", addr);

            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let nbytes = socket
                    .read(&mut buf)
                    .await
                    .expect("Error reading from socket");

                if nbytes > 0 {
                    let received_message = String::from_utf8_lossy(&buf[..nbytes]);
                    let received_message = received_message.trim_matches(char::from(0));
                    tx_clone
                        .send(received_message.to_string())
                        .await
                        .expect("Error sending message to channel");
                    println!("Message received: {}", received_message);
                    // Echo the received message back to the client
                    if let Err(e) = socket.write_all(received_message.as_bytes()).await {
                        println!("Failed to send back the message: {}", e);
                    }
                } else {
                    let error_message = "No data received from client";
                    println!("{}", error_message);
                    tx_clone
                        .send(error_message.to_string())
                        .await
                        .expect("Error sending error message to channel");
                }
            });

            // Receive the message or error from the channel
            let message = rx.recv().await.expect("Error receiving from channel");
            if message == "No data received from client" {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    message,
                )));
            }
            // Otherwise, you can continue processing the message or do something else.
            // Since we're in a loop, we'll go back and wait for the next connection.
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
