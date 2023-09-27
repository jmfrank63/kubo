// use std::ffi::{CStr, CString};
// use std::os::raw::c_char;

// #[repr(C)]
// pub struct Result {
//     pub data: *mut c_char,
//     pub error: *mut c_char,
// }

// #[no_mangle]
// pub extern "C" fn start_client() -> *mut Result {
//     let rt = tokio::runtime::Runtime::new().unwrap();

//     let result: Box<Result> = Box::new(rt.block_on(async {
//         let mut response = Result {
//             data: std::ptr::null_mut(),
//             error: std::ptr::null_mut(),
//         };

//         // Simulate reading "Hello from Rust" from the stream
//         let simulated_msg = "Hello from Client Plugin in Rust!";
//         let buf = CString::new(simulated_msg).unwrap().into_bytes_with_nul().to_vec();

//         let received_msg = CStr::from_bytes_with_nul(&buf).unwrap_or_default();
//         response.data = CString::new(received_msg.to_str().unwrap_or_default())
//             .unwrap()
//             .into_raw();
//         response
//     }));

//     Box::into_raw(result)
// }

use std::ffi::CString;
use std::os::raw::c_char;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::tcp::Socks5Stream;
use tokio_socks::Error as SocksError;
use tokio_socks::TargetAddr;

#[repr(C)]
pub struct Result {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

#[no_mangle]
pub extern "C" fn start_client() -> *mut Result {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let result: Box<Result> = Box::new(rt.block_on(async {
        let mut response = Result {
            data: std::ptr::null_mut(),
            error: std::ptr::null_mut(),
        };

        // Connect via SOCKS5 proxy
        let target = TargetAddr::Domain("172.18.0.2".into(), 2000);
        let proxy: std::net::SocketAddr = "172.19.0.3:1080".parse().unwrap();

        let mut stream = match Socks5Stream::connect_with_password(proxy, target, "socks", "socks")
            .await
        {
            Ok(s) => s,
            Err(SocksError::AuthorizationRequired) => {
                response.error = CString::new("Authentication failed").unwrap().into_raw();
                return response;
            }
            Err(e) => {
                response.error = CString::new(format!("Failed to connect through proxy: {}", e))
                    .unwrap()
                    .into_raw();
                return response;
            }
        };

        // Send message "Hello from client"
        let message = "Hello from client";
        if let Err(e) = stream.write_all(message.as_bytes()).await {
            response.error = CString::new(format!("Failed to send message: {}", e))
                .unwrap()
                .into_raw();
            return response;
        }

        // Optional: If you want to read a response from the server, do so here.
        let mut buf = vec![0u8; 1024];
        let nbytes = stream.read(&mut buf).await.unwrap_or(0);
        if nbytes > 0 {
            let received_message = String::from_utf8_lossy(&buf[..nbytes]);
            let received_message = received_message.trim_matches(char::from(0));
            response.data = CString::new(received_message).unwrap().into_raw();
        }

        response
    }));

    Box::into_raw(result)
}
