use std::os::raw::c_char;
use std::ffi::CString;
use tokio::net::{TcpListener};
use tokio::io::AsyncWriteExt;

#[no_mangle]
pub extern "C" fn start_server() -> *mut c_char {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Use block_on to run an async function and wait for its result
    let result = rt.block_on(async {
        // Start a listener on a specific address and port
        let listener = TcpListener::bind("0.0.0.0:5555").await.unwrap();

        // Wait for a connection
        if let Ok((mut socket, _)) = listener.accept().await {
            // Send the "Server Started" message to the connected client
            let _ = socket.write_all(b"Server Started").await;
        }

        "Server Started and message sent!"
    });

    let s = CString::new(result).unwrap();
    s.into_raw()
}
