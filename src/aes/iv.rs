use std::fmt::Display;

use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use crate::CryptError;

/// Initialization Vector for AES encryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Iv {
    bytes: [u8; 16],
}
impl Iv {
    /// Create a new `Iv` with random bytes.
    pub fn new() -> Result<Self, CryptError> {
        Ok(Self {
            bytes: Self::generate_iv()?,
        })
    }

    /// Get the IV bytes.
    pub fn get_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Generate a 16 byte random iv.
    fn generate_iv() -> Result<[u8; 16], CryptError> {
        let mut key: [u8; 16] = [0; 16];
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
        assert_eq!(iv.get_bytes().len(), 16);
    }
}
