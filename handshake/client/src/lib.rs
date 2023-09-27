use std::ffi::{CString, CStr};
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

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and points to
/// a valid object of the appropriate type.
#[no_mangle]
pub unsafe extern "C" fn start_client(peer_id: *const c_char) -> *mut Result {
    let peer_id = unsafe {
        assert!(!peer_id.is_null());
        CStr::from_ptr(peer_id)
     };

    println!("Peer id: {}", peer_id.to_str().unwrap());
    let rt = tokio::runtime::Runtime::new().unwrap();

    let result: Box<Result> = Box::new(rt.block_on(async {
        let mut response = Result {
            data: std::ptr::null_mut(),
            error: std::ptr::null_mut(),
        };
            // Connect via SOCKS5 proxy
            let target = TargetAddr::Domain("172.18.0.2".into(), 2000);
            let proxy: std::net::SocketAddr = "172.19.0.3:1080".parse().unwrap();

            let mut stream =
                match Socks5Stream::connect_with_password(proxy, target, "socks", "socks").await {
                    Ok(s) => s,
                    Err(SocksError::AuthorizationRequired) => {
                        response.error = CString::new("Authentication failed").unwrap().into_raw();
                        return response;
                    }
                    Err(e) => {
                        response.error =
                            CString::new(format!("Failed to connect through proxy: {}", e))
                                .unwrap()
                                .into_raw();
                        return response;
                    }
                };

            let message = "Hello from client";

            if let Err(e) = stream.write_all(message.as_bytes()).await {
                response.error = CString::new(format!("Failed to send message: {}", e))
                    .unwrap()
                    .into_raw();
                return response;
            }
            println!("Sent {} bytes", message.as_bytes().len());
            if let Err(e) = stream.flush().await {
                response.error = CString::new(format!("Failed to flush stream {}", e))
                    .unwrap()
                    .into_raw();
                return response;
            }

            let mut buf = vec![0u8; 1024];
            let nbytes = stream.read(&mut buf).await.unwrap_or(0);
            println!("Received {} bytes", nbytes);
            if nbytes > 0 {
                let received_message = String::from_utf8_lossy(&buf[..nbytes]);
                let received_message = received_message.trim_matches(char::from(0));
                println!("Received message: {}", received_message);
                response.data = CString::new(received_message).unwrap().into_raw();
            }

        response
    }));

    Box::into_raw(result)
}
