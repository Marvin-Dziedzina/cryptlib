use std::fmt::Display;

use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use crate::CryptError;

/// Initialization Vector for AES encryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Iv {
    bytes: [u8; 12],
}
impl Iv {
    /// Create a new `Iv` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the random bytes generation fails.
    pub fn new() -> Result<Self, CryptError> {
        Ok(Self {
            bytes: Self::generate_iv()?,
        })
    }

    /// Get the IV bytes.
    pub fn get_bytes(&self) -> &[u8; 12] {
        &self.bytes
    }

    /// Generate a 12 byte random iv with cryptographically strong pseudo-random bytes.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if `rand_bytes()` fails.
    fn generate_iv() -> Result<[u8; 12], CryptError> {
        let mut key: [u8; 12] = [0; 12];
        rand_bytes(&mut key).map_err(CryptError::RandError)?;

        Ok(key)
    }
}

impl Display for Iv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.bytes)
    }
}

mod tests {
    #[test]
    fn test_iv_creation() {
        let iv = crate::aes::Iv::new().unwrap();
        assert_eq!(iv.get_bytes().len(), 12);
    }
}
