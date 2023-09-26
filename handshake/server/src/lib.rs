use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)]
pub struct Result {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

#[no_mangle]
pub extern "C" fn start_server() -> *mut Result {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let result: Box<Result> = Box::new(rt.block_on(async {
        let mut response = Result {
            data: std::ptr::null_mut(),
            error: std::ptr::null_mut(),
        };

        // Simulate reading "Hello from Rust" from the stream
        let simulated_msg = "Hello from Server Plugin in Rust!";
        let buf = CString::new(simulated_msg).unwrap().into_bytes_with_nul().to_vec();

        let received_msg = CStr::from_bytes_with_nul(&buf).unwrap_or_default();
        response.data = CString::new(received_msg.to_str().unwrap_or_default())
            .unwrap()
            .into_raw();
        response
    }));

    Box::into_raw(result)
}
