// use std::ffi::CString;
// use std::net::SocketAddr;
// use std::os::raw::c_char;
// use tokio::io::AsyncReadExt;
// use tokio::net::TcpListener;

// #[repr(C)]
// pub struct Result {
//     pub data: *mut c_char,
//     pub error: *mut c_char,
// }

// #[no_mangle]
// pub extern "C" fn start_server() -> *mut Result{
//     // Create a result object
//     let mut result = Box::new(Result {
//         data: std::ptr::null_mut(),
//         error: std::ptr::null_mut(),
//     });

//     // Create the tokio runtime
//     let rt = match tokio::runtime::Runtime::new() {
//         Ok(rt) => rt,
//         Err(e) => {
//             let error_message = format!("Error creating runtime: {}", e);
//             result.error = CString::new(error_message).unwrap().into_raw();
//             return Box::into_raw(result);
//         }
//     };

//     result = rt.block_on(async {
//         // Bind to port 2000
//         let listener = match TcpListener::bind("172.18.0.2:2000").await {
//             Ok(listener) => listener,
//             Err(e) => {
//                 let error_message = format!("Error binding to port 2000: {}", e);
//                 result.error = CString::new(error_message)
//                     .expect("Conversion into CString failed")
//                     .into_raw();
//                 return result;
//             }
//         };
//         println!("Listening on: {}", listener.local_addr().unwrap());

//         loop {
//             // Await a connection and read the message
//             let (mut socket, addr) = match listener.accept().await {
//                 Ok((socket, addr)) => (socket, addr),
//                 Err(e) => {
//                     let error_message = format!("Error accepting connection: {}", e);
//                     result.error = CString::new(error_message).unwrap().into_raw();
//                     return result;
//                 }
//             };

//             // return an error if addr is not 172.18.0.2:2000
//             let expected_addr = SocketAddr::from(([172, 18, 0, 2], 2000));
//             if addr != expected_addr {
//                 let error_message = format!("Expected addr: {:?}, got: {:?}", expected_addr, addr);
//                 result.error = CString::new(error_message).unwrap().into_raw();
//                 return result;
//             } else {
//                 println!("Got connection from: {:?}", addr);
//             }

//             tokio::spawn(async move {let mut buf = [0u8; 1024];
//             let nbytes = socket.read(&mut buf).await.unwrap();

//             if nbytes > 0 {
//                 let received_message = String::from_utf8_lossy(&buf[..nbytes]);
//                 let received_message = received_message.trim_matches(char::from(0));
//                 let received_message = CString::new(received_message).unwrap().into_raw();
//                 result.data = received_message;
//             } else {
//                 let error_message = "No data received from client";
//                 result.error = CString::new(error_message).unwrap().into_raw();
//             }});
//         }
//     });

//     Box::into_raw(result)
// }

use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::c_char;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[repr(C)]
pub struct Result {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

#[no_mangle]
pub extern "C" fn start_server() -> *mut Result {
    // Create a result object
    let mut result = Box::new(Result {
        data: std::ptr::null_mut(),
        error: std::ptr::null_mut(),
    });

    // Create the tokio runtime
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let error_message = format!("Error creating runtime: {}", e);
            result.error = CString::new(error_message).unwrap().into_raw();
            return Box::into_raw(result);
        }
    };

    // Create an asynchronous channel
    let (tx, mut rx) = mpsc::channel(32);

    result = rt.block_on(async {
        // Bind to port 2000
        let listener = match TcpListener::bind("172.18.0.2:2000").await {
            Ok(listener) => listener,
            Err(e) => {
                let error_message = format!("Error binding to port 2000: {}", e);
                result.error = CString::new(error_message)
                    .expect("Conversion into CString failed")
                    .into_raw();
                return result;
            }
        };
        println!("Listening on: {}", listener.local_addr().unwrap());

        loop {
            // Await a connection and read the message
            let (mut socket, addr) = match listener.accept().await {
                Ok((socket, addr)) => (socket, addr),
                Err(e) => {
                    let error_message = format!("Error accepting connection: {}", e);
                    result.error = CString::new(error_message).unwrap().into_raw();
                    return result;
                }
            };
            println!("Got connection from: {:?}", addr);

            let tx_clone = tx.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let nbytes = socket.read(&mut buf).await.unwrap();

                if nbytes > 0 {
                    let received_message = String::from_utf8_lossy(&buf[..nbytes]);
                    let received_message = received_message.trim_matches(char::from(0));
                    tx_clone.send(received_message.to_string()).await.unwrap();
                    println!("Message received: {}", received_message);
                } else {
                    let error_message = "No data received from client";
                    println!("{}", error_message);
                    tx_clone.send(error_message.to_string()).await.unwrap();
                }
            });

            // Receive the message or error from the channel
            let message = rx.recv().await.unwrap();
            if message == "No data received from client" {
                result.error = CString::new(message).unwrap().into_raw();
            } else {
                result.data = CString::new(message).unwrap().into_raw();
            }
        }
    });

    Box::into_raw(result)
}
