extern crate curve25519_dalek;
extern crate rand;

use crate::errors::DynError;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{cell::RefCell, pin::Pin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::Rng;
use tokio::time::timeout;

const NONCE_SIZE: usize = 12;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;
const RECV_TIMEOUT: Duration = Duration::from_secs(30);
const READ_ITERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CHUNK_SIZE: usize = 4096;

/// Represents an asymmetric keypair.
pub struct Keypair {
    /// The private asymmetric key
    pub private: Vec<u8>,
    /// The public asymmetric key
    pub public: Vec<u8>,
}

enum ReadState {
    ReadingLength,
    ReadingData(usize), // usize stores the expected message length
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin {}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for S {}

pub struct EncryptedTcpStream<S: Stream> {
    inner: S,
    secret: Vec<u8>,
    nonce: RefCell<Nonce>,
    read_state: ReadState,
    read_buffer: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedTcpStream<S> {
    pub async fn send(&mut self, buf: &[u8]) -> Result<(), Box<dyn std::error::Error + Send>> {
        // Encrypt the data with the current nonce
        let encrypted_data = self.encrypt(buf).map_err(|e| Box::new(e) as DynError)?;

        // Fetch and serialize the nonce
        let combined_data = {
            let nonce = self.nonce.borrow();
            let mut combined_data = Vec::new();
            combined_data.extend_from_slice(&nonce);
            combined_data.extend_from_slice(&encrypted_data);
            combined_data
        };

        let total_len = combined_data.len();
        let msg_len_buf = [(total_len >> 8) as u8, (total_len & 0xff) as u8];

        // First, send the length
        self.inner
            .write_all(&msg_len_buf)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

        // Then send the message in chunks
        let mut bytes_sent = 0;
        while bytes_sent < total_len {
            let end = bytes_sent + CHUNK_SIZE.min(total_len - bytes_sent);
            self.inner
                .write_all(&combined_data[bytes_sent..end])
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
            bytes_sent = end;
        }
        Ok(())
    }

    async fn read_data_from_stream(&mut self) -> Result<(), Box<dyn std::error::Error + Send>> {
        // First, read the length bytes (only two bytes) if we are in ReadingLength state
        if matches!(self.read_state, ReadState::ReadingLength) {
            let mut msg_len_buf = [0u8; 2];
            self.inner
                .read_exact(&mut msg_len_buf)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
            let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
            // Size check to prevent over-allocation
            if msg_len > MAX_MESSAGE_SIZE {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Message too long",
                )));
            }

            // Resize the buffer to the expected message length
            self.read_buffer.clear();
            self.read_buffer.resize(msg_len, 0);

            // Transition to the ReadingData state
            self.read_state = ReadState::ReadingData(msg_len);
        }

        let mut bytes_read = 0;
        let target_length = self.read_buffer.len();

        while bytes_read < target_length {
            let remaining = target_length - bytes_read;

            // The `min` function ensures we don't try to read more than available in our buffer
            let read_slice =
                &mut self.read_buffer[bytes_read..bytes_read + remaining.min(CHUNK_SIZE)];

            let read_result = timeout(READ_ITERATION_TIMEOUT, {
                self.inner.read(read_slice)
            })
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;

            if read_result == 0 {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                )));
            }
            bytes_read += read_result;
        }

        // Transition back to ReadingLength state
        self.read_state = ReadState::ReadingLength;

        Ok(())
    }

    fn decrypt_received_data(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send>> {
        // Split the nonce and the encrypted message
        let (nonce_bytes, encrypted_data) = self.read_buffer.split_at(NONCE_SIZE);

        // Update the current nonce to the one from the received data
        let nonce = {
            let mut current_nonce = self.nonce.borrow_mut();
            current_nonce.copy_from_slice(nonce_bytes);
            current_nonce
        };

        // Decrypt the received data using the nonce
        self.decrypt(encrypted_data, &nonce)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send>> {
        // Set a timeout for the entire receive operation
        let result = timeout(RECV_TIMEOUT, async {
            self.read_data_from_stream().await?;
            self.decrypt_received_data()
        })
        .await;

        // Check the result of the timeout
        match result {
            Ok(res) => res,
            Err(_) => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Recv operation timed out",
            ))),
        }
    }
}

impl<S: Stream> EncryptedTcpStream<S> {
    pub fn new(inner: S, secret: Vec<u8>) -> Self {
        let nonce = RefCell::new(ChaCha20Poly1305::generate_nonce(&mut OsRng));
        EncryptedTcpStream {
            inner,
            secret,
            nonce,
            read_state: ReadState::ReadingLength,
            read_buffer: Vec::new(),
        }
    }

    pub fn upgrade(inner: S, secret: Vec<u8>) -> Self {
        let nonce = RefCell::new(ChaCha20Poly1305::generate_nonce(&mut OsRng));
        EncryptedTcpStream {
            inner,
            secret,
            nonce,
            read_state: ReadState::ReadingLength,
            read_buffer: Vec::new(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        self.increment_nonce();
        let result = encrypt(&self.secret, data, &self.nonce.borrow());

        result
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &Nonce,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        decrypt(&self.secret, ciphertext, nonce)
    }

    fn increment_nonce(&self) {
        for byte in self.nonce.borrow_mut().iter_mut().rev() {
            if *byte == u8::MAX {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
    }
}

impl<S: Stream> AsyncRead for EncryptedTcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Buffer to hold the nonce and the encrypted data
        let mut temp_buf = vec![0u8; NONCE_SIZE + buf.remaining()];

        // Read the nonce and the encrypted data
        let mut temp_read_buf = tokio::io::ReadBuf::new(&mut temp_buf);
        let inner_poll = Pin::new(&mut self.inner).poll_read(cx, &mut temp_read_buf);

        match inner_poll {
            Poll::Ready(Ok(_)) => {
                // Split the temp_buf into nonce and data parts
                let (nonce, encrypted_data) = temp_buf.split_at(NONCE_SIZE);

                // Convert the nonce slice into your Nonce type
                let nonce = Nonce::from_slice(nonce); // Assuming Nonce has such a method

                // Now, decrypt using the nonce and the encrypted data
                let decrypted_data = self.decrypt(encrypted_data, nonce).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")
                })?;

                // Put the decrypted data into the provided buffer
                buf.put_slice(&decrypted_data);

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: Stream> AsyncWrite for EncryptedTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let encrypted_data = self.encrypt(buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed")
        })?;
        Pin::new(&mut self.inner).poll_write(cx, &encrypted_data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Generates a new keypair using the curve25519-dalek library.
///
/// # Returns
///
/// A `Result` which is:
///
/// - `Ok(Keypair)`: If the key generation succeeded.
/// - `Err(DynError)`: If there was an error during generation.
pub fn generate_keypair() -> Result<Keypair, DynError> {
    let secret_scalar = generate_random_scalar();
    let public_point = secret_scalar * constants::RISTRETTO_BASEPOINT_POINT;
    // Convert the Scalar and RistrettoPoint to Vec<u8>
    let secret_bytes = secret_scalar.to_bytes().to_vec();
    let public_bytes = public_point.compress().to_bytes().to_vec();

    Ok(Keypair {
        private: secret_bytes,
        public: public_bytes,
    })
}

/// Generates a random scalar using the curve25519-dalek library.
///
/// # Returns
///
/// A `Scalar` which represents the randomly generated scalar value.
fn generate_random_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill(&mut random_bytes);
    Scalar::from_bytes_mod_order(random_bytes)
}

/// Perform the DH operation.
///
/// `my_private` is your private key, and `their_public` is the other party's public key.
pub fn diffie_hellman(
    my_private_key: &[u8],
    their_public_key: &[u8],
) -> Result<RistrettoPoint, DynError> {
    let my_private = Scalar::from_bytes_mod_order(slice_to_array(my_private_key));
    let their_public = CompressedRistretto::from_slice(their_public_key)
        .map_err(|e| Box::new(e) as DynError)?
        .decompress()
        .ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to decompress public key",
            )) as DynError
        })?;
    Ok(their_public * my_private)
}

/// Computes a combined key by mixing the Diffie-Hellman shared secret and a pre-shared key (PSK).
///
/// This function uses the Blake2s hashing algorithm to combine the DH secret and the PSK.
/// The result can then be used as a symmetric key in subsequent cryptographic operations.
///
/// # Arguments
///
/// * `dh_secret` - A shared secret derived from the Diffie-Hellman exchange.
/// * `psk`       - A pre-shared key agreed upon by both parties out-of-band.
///
/// # Returns
///
/// A `Vec<u8>` containing the mixed key.
pub fn mix_keys(dh_secret: &[u8], psk: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(dh_secret);
    hasher.update(psk);
    hasher.finalize().to_vec()
}

/// Encrypts the provided data using the ChaCha20Poly1305 encryption algorithm.
///
/// # Parameters
///
/// - `secret`: The secret key used for encryption.
/// - `data`: The plaintext data to be encrypted.
///
/// # Returns
///
/// Returns an `Ok` variant containing the encrypted data (ciphertext) if the encryption process
/// succeeds, or an `Err` variant with the associated error if it fails.
pub fn encrypt(
    secret: &[u8],
    data: &[u8],
    nonce: &Nonce,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = chacha20poly1305::Key::from_slice(secret); // Our shared secret
    let cipher = ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, data)
}

/// Decrypts the provided ciphertext using the ChaCha20Poly1305 encryption algorithm.
///
/// # Parameters
///
/// - `secret`: The secret key used for decryption.
/// - `ciphertext`: The encrypted data to be decrypted.
///
/// # Returns
///
/// Returns an `Ok` variant containing the decrypted data (plaintext) if the decryption process
/// succeeds, or an `Err` variant with the associated error if it fails.
pub fn decrypt(
    secret: &[u8],
    ciphertext: &[u8],
    nonce: &Nonce,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = chacha20poly1305::Key::from_slice(secret);
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext)
}

/// Decodes the encoded shared secret string into its byte representation.
///
/// The function expects the encoded shared secret to be in a specific format.
///
/// # Parameters
///
/// - `encoded`: The encoded string representation of the shared secret.
///
/// # Returns
///
/// Returns an `Ok` variant containing the decoded byte representation of the shared secret if the
/// decoding process succeeds, or an `Err` variant with the associated error if it fails.
pub fn decode_shared_secret(encoded: &str) -> Result<Vec<u8>, DynError> {
    // Split the input string by the newline character to get the individual lines
    let lines: Vec<&str> = encoded.split('\n').collect();

    // Ensure there are at least 3 lines in the split result
    if lines.len() < 3 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid shared secret format",
        )) as DynError);
    }

    // Decode the last line, which contains the hex-encoded shared secret
    hex::decode(lines[2]).map_err(|e| Box::new(e) as DynError)
}

// Helper function to convert a slice to an array
fn slice_to_array(slice: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    array.copy_from_slice(slice);
    array
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.private.len(), 32);
        assert_eq!(keypair.public.len(), 32);
    }

    #[test]
    fn test_generate_random_scalar() {
        let scalar = generate_random_scalar();
        // Ensure the scalar is not zero.
        // This is a simple check; in reality, the chance of generating a zero scalar is negligible.
        assert_ne!(scalar, Scalar::ZERO);
    }

    #[test]
    fn test_diffie_hellman() {
        // Alice generates her keypair
        let alice_keypair = generate_keypair().unwrap();

        // Bob generates his keypair
        let bob_keypair = generate_keypair().unwrap();

        // Alice computes the shared secret using her private key and Bob's public key
        let alice_shared_secret =
            diffie_hellman(&alice_keypair.private, &bob_keypair.public).unwrap();

        // Bob computes the shared secret using his private key and Alice's public key
        let bob_shared_secret =
            diffie_hellman(&bob_keypair.private, &alice_keypair.public).unwrap();

        // The shared secrets should be identical
        assert_eq!(
            alice_shared_secret, bob_shared_secret,
            "Shared secrets are not identical!"
        );
    }

    #[test]
    fn test_mix_keys() {
        // Sample values for this test
        let alice_keypair = generate_keypair().unwrap();
        let bob_keypair = generate_keypair().unwrap();

        let dh_secret = diffie_hellman(&alice_keypair.private, &bob_keypair.public)
            .unwrap()
            .compress()
            .to_bytes();

        let psk = b"This is a test PSK!!";
        assert_eq!(psk.len(), 20); // ensure our sample PSK is 20 bytes

        let mixed_key = mix_keys(&dh_secret, psk);

        // Ensure that the mixed_key is neither the DH secret nor the PSK
        assert_ne!(mixed_key, dh_secret.to_vec());
        assert_ne!(mixed_key, psk.to_vec());
    }

    #[test]
    fn test_shared_symmetric_key_derivation() {
        // PSK: In a real-world scenario, ensure it's derived securely.
        let psk = b"SuperSecretPSK123"; // 16 bytes for our example

        // Alice and Bob generate their keypairs
        let alice_keypair = generate_keypair().unwrap();
        let bob_keypair = generate_keypair().unwrap();

        // Alice computes the DH secret using her private key and Bob's public key
        let alice_dh_secret = diffie_hellman(&alice_keypair.private, &bob_keypair.public).unwrap();
        // Alice mixes the DH secret with the PSK to derive the shared symmetric key
        let alice_symmetric_key = mix_keys(&alice_dh_secret.compress().to_bytes(), psk);

        // Bob computes the DH secret using his private key and Alice's public key
        let bob_dh_secret = diffie_hellman(&bob_keypair.private, &alice_keypair.public).unwrap();
        // Bob mixes the DH secret with the PSK to derive the shared symmetric key
        let bob_symmetric_key = mix_keys(&bob_dh_secret.compress().to_bytes(), psk);

        // Both derived keys should be identical
        assert_eq!(
            alice_symmetric_key, bob_symmetric_key,
            "Derived symmetric keys are not identical!"
        );
    }

    #[test]
    fn test_mismatched_psk_derivation() {
        // Generate keypairs for Alice and Bob
        let alice_keypair = generate_keypair().unwrap();
        let bob_keypair = generate_keypair().unwrap();

        // Calculate the DH secret from both perspectives
        let alice_dh_secret = diffie_hellman(&alice_keypair.private, &bob_keypair.public).unwrap();
        let bob_dh_secret = diffie_hellman(&bob_keypair.private, &alice_keypair.public).unwrap();

        // Use correct PSK for Alice and a different PSK for Bob
        let correct_psk = b"Correct PSK";
        let incorrect_psk = b"Incorrect PSK";

        let alice_mixed_key = mix_keys(&alice_dh_secret.compress().to_bytes(), correct_psk);
        let bob_mixed_key = mix_keys(&bob_dh_secret.compress().to_bytes(), incorrect_psk);

        // The mixed keys should be different due to different PSKs
        assert_ne!(
            alice_mixed_key, bob_mixed_key,
            "Keys unexpectedly matched despite mismatched PSKs!"
        );
    }

    #[test]
    fn test_decode_shared_secret() {
        let encoded = "/key/swarm/psk/1.0.0/\n/base16/\nb014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351";

        let decoded = decode_shared_secret(encoded).expect("Failed to decode the shared secret");
        let expected =
            hex::decode("b014416087025d9e34862cedb87468f2a2e2b6cd99d288107f87a0641328b351")
                .expect("Failed to decode the expected value");

        assert_eq!(decoded, expected);
    }

    const SECRET_LENGTH: usize = 32;

    #[test]
    fn test_encrypt_decrypt() {
        let secret = b"This is a very very secret key!!"; // ensure it's of appropriate length
        assert_eq!(secret.len(), SECRET_LENGTH);
        let data = b"Hello, world!";
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        // Encrypt the data
        let encrypted_data = encrypt(secret, data, &nonce).expect("Encryption failed");
        assert_ne!(encrypted_data.as_slice(), data);

        // Decrypt the data back
        let decrypted_data = decrypt(secret, &encrypted_data, &nonce).expect("Decryption failed");
        assert_eq!(decrypted_data.as_slice(), data);
    }

    #[test]
    fn test_decrypt_with_wrong_secret() {
        let secret1 = b"This is a very very secret key!!";
        assert_eq!(secret1.len(), SECRET_LENGTH);
        let secret2 = b"This is another very secret key!";
        assert_eq!(secret2.len(), SECRET_LENGTH);
        let data = b"Hello, world!";
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        // Encrypt the data with the first secret
        let encrypted_data = encrypt(secret1, data, &nonce).expect("Encryption failed");

        // Attempt to decrypt with the wrong secret
        let result = decrypt(secret2, &encrypted_data, &nonce);
        assert!(
            result.is_err(),
            "Expected an error when decrypting with a wrong secret"
        );
    }

    #[tokio::test]
    async fn test_basic_encryption_decryption() {
        let secret = b"test_secret_padded_with_zeros_!!".to_vec();

        let (stream1, stream2) = tokio::io::duplex(10);

        let mut encrypted_stream1 = EncryptedTcpStream::new(stream1, secret.clone());
        let mut encrypted_stream2 = EncryptedTcpStream::new(stream2, secret.clone());

        let test_data = b"Hello, World!".to_vec();
        let test_data2 = test_data.clone();

        // Send data through the first stream
        let sender = tokio::spawn(async move {
            encrypted_stream1.send(&test_data).await.unwrap();
        });

        let receiver = tokio::spawn(async move {
            let received_data = encrypted_stream2.recv().await.unwrap();
            assert_eq!(received_data, test_data2);
        });

        sender.await.unwrap();
        receiver.await.unwrap();

    }

    #[tokio::test]
    async fn test_basic_encryption_decryption_reverse() {
        let secret = b"test_secret_padded_with_zeros_!!".to_vec();

        let (stream1, stream2) = tokio::io::duplex(10);

        let mut encrypted_stream1 = EncryptedTcpStream::new(stream1, secret.clone());
        let mut encrypted_stream2 = EncryptedTcpStream::new(stream2, secret.clone());

        let test_data = b"Hello, World!".to_vec();
        let test_data2 = test_data.clone();

        // Send data through the first stream
        let sender = tokio::spawn(async move {
            encrypted_stream2.send(&test_data).await.unwrap();
        });

        let receiver = tokio::spawn(async move {
            let received_data = encrypted_stream1.recv().await.unwrap();
            assert_eq!(received_data, test_data2);
        });

        sender.await.unwrap();
        receiver.await.unwrap();

    }
}
