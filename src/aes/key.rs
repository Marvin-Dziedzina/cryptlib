use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use crate::CryptError;

/// Stores the AES key
#[derive(Debug, Serialize, Deserialize)]
pub struct AesKey {
    key: [u8; 32],
}
impl AesKey {
    /// Create new instance of AesKey. This generates a new key.
    pub fn new() -> Result<Self, CryptError> {
        Ok(Self {
            key: Self::generate_key_32bytes()?,
        })
    }

    /// Creates a new instance from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Create `AesKey` instance from a key vec.
    pub fn from_vec(vec: &[u8]) -> Result<Self, CryptError> {
        if vec.len() != 32 {
            return Err(CryptError::AesKeyError(String::from(
                "Key lenght is not 32 bits!",
            )));
        };

        let mut key: [u8; 32] = [0; 32];
        key.clone_from_slice(vec);

        Ok(Self { key })
    }

    /// Get the bytes of the key.
    pub fn get_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Generate a 32 byte random key.
    fn generate_key_32bytes() -> Result<[u8; 32], CryptError> {
        let mut key = [0; 32];
        rand_bytes(&mut key).map_err(CryptError::RandError)?;

        Ok(key)
    }
}

impl Clone for AesKey {
    fn clone(&self) -> Self {
        Self {
            key: self.get_bytes(),
        }
    }
}

pub struct EncryptedAesKey {
    encrypted_key: String,
}
impl EncryptedAesKey {
    pub fn new(encrypted_key: String) -> Self {
        Self { encrypted_key }
    }

    pub fn get_component(self) -> String {
        self.encrypted_key
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_new() {
        let aes_key = AesKey::new();
        assert!(aes_key.is_ok());
        let key = aes_key.unwrap().get_bytes();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aes_key_from_bytes() {
        let bytes = [1u8; 32];
        let aes_key = AesKey::from_bytes(bytes);
        assert_eq!(aes_key.get_bytes(), bytes);
    }

    #[test]
    fn test_aes_key_from_vec_valid() {
        let vec = vec![1u8; 32];
        let aes_key = AesKey::from_vec(&vec);
        assert!(aes_key.is_ok());
        assert_eq!(aes_key.unwrap().get_bytes(), [1u8; 32]);
    }

    #[test]
    fn test_aes_key_from_vec_invalid() {
        let vec = vec![1u8; 31];
        let aes_key = AesKey::from_vec(&vec);
        assert!(aes_key.is_err());
    }

    #[test]
    fn test_aes_key_clone() {
        let aes_key = AesKey::new().unwrap();
        let cloned_key = aes_key.clone();
        assert_eq!(aes_key.get_bytes(), cloned_key.get_bytes());
    }

    #[test]
    fn test_encrypted_aes_key_new() {
        let encrypted_key = String::from("encrypted_key");
        let encrypted_aes_key = EncryptedAesKey::new(encrypted_key.clone());
        assert_eq!(encrypted_aes_key.get_component(), encrypted_key);
    }
}
