pub mod errors;
pub mod noise;
pub mod handshake;
pub mod mock;

use std::ffi::{c_char, CString};

use errors::HandshakeError;
use noise::{Keypair, diffie_hellman, decode_shared_secret, mix_keys};

pub const TEST_SECRET: &[u8] = b"This is a very very secret key!!";
pub const LOOP_DELAY: u64 = 1000;
pub const PROXY_ADDR: &str = "172.19.0.3:1080";
pub const SERVER_ADDR: &str = "172.18.0.2:2000";
pub const SWARM_KEY: &str = "/key/swarm/psk/1.0.0/
/base16/
b014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351
";
/// Represents a result for FFI with either data or an error.
///
/// - `data`: Success outcome, null if error is present.
/// - `error`: Error message, null if data is present.
///
/// Consumers MUST free the allocated memory for `data` and `error`.
#[repr(C)]
pub struct FFIResult {
    pub data: *mut c_char,
    pub error: *mut c_char,
}

pub fn convert_rust_result_to_ffi_result(
    res: std::result::Result<String, HandshakeError>,
) -> *mut FFIResult {
    match res {
        Ok(data) => {
            let data_cstr = match CString::new(data) {
                Ok(cstr) => cstr,
                Err(_) => CString::new("Invalid string with null byte")
                    .expect("Static string should not fail"),
            };
            Box::into_raw(Box::new(FFIResult {
                data: data_cstr.into_raw(),
                error: std::ptr::null_mut(),
            }))
        }
        Err(e) => {
            let error_cstr = match CString::new(e.to_string()) {
                Ok(cstr) => cstr,
                Err(_) => CString::new("Error converting to CString")
                    .expect("Static string should not fail"),
            };
            Box::into_raw(Box::new(FFIResult {
                data: std::ptr::null_mut(),
                error: error_cstr.into_raw(),
            }))
        }
    }
}

pub fn generate_shared_secret(
    their_public_key: &[u8],
    key_pair: Keypair,
    swarm_key: &str,
) -> Result<Vec<u8>, HandshakeError> {
    let private_key = key_pair.private.as_slice();
    let ristretto_point = diffie_hellman(private_key, their_public_key)?;
    let dh_secret = ristretto_point.compress().to_bytes();
    let pre_shared_key = decode_shared_secret(swarm_key)?;
    let shared_secret = mix_keys(&dh_secret, &pre_shared_key);
    Ok(shared_secret)
}
