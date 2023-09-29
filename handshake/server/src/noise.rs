extern crate curve25519_dalek;
extern crate rand;

use crate::errors::DynError;

use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;

/// Represents an asymmetric keypair.
pub struct Keypair {
    /// The private asymmetric key
    pub private: Vec<u8>,
    /// The public asymmetric key
    pub public: Vec<u8>,
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
}
