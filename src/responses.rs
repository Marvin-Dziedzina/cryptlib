use serde::{Deserialize, Serialize};

use crate::{aes::AesCiphertext, rsa::RsaCiphertext};

/// `CiphertextData` is a struct that holds the encrypted aes key and the aes encrypted data.
/// It is used to decrypt the data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CiphertextData {
    rsa_ciphertext: RsaCiphertext,
    aes_ciphertext: AesCiphertext,
}
impl CiphertextData {
    /// Create a new `CiphertextData` struct.
    pub fn new(rsa_ciphertext: RsaCiphertext, aes_ciphertext: AesCiphertext) -> Self {
        Self {
            rsa_ciphertext,
            aes_ciphertext,
        }
    }

    /// Get the components of the `CiphertextData` struct.
    pub fn get_components(self) -> (RsaCiphertext, AesCiphertext) {
        (self.rsa_ciphertext, self.aes_ciphertext)
    }
}
#[cfg(test)]
mod tests {
    use crate::aes::Iv;

    use super::*;

    #[test]
    fn test_ciphertext_data_creation() {
        let rsa_ciphertext = RsaCiphertext::new(vec![1, 2, 3, 4]);
        let aes_ciphertext = AesCiphertext::new(
            false,
            vec![5, 6, 7, 8],
            Iv::new().unwrap(),
            vec![9, 10, 11, 12],
            [1; 16],
        );
        let ciphertext_data = CiphertextData::new(rsa_ciphertext.clone(), aes_ciphertext.clone());

        assert_eq!(ciphertext_data.rsa_ciphertext, rsa_ciphertext);
        assert_eq!(ciphertext_data.aes_ciphertext, aes_ciphertext);
    }

    #[test]
    fn test_get_components() {
        let rsa_ciphertext = RsaCiphertext::new(vec![1, 2, 3, 4]);
        let aes_ciphertext = AesCiphertext::new(
            false,
            vec![5, 6, 7, 8],
            Iv::new().unwrap(),
            vec![9, 10, 11, 12],
            [1; 16],
        );
        let ciphertext_data = CiphertextData::new(rsa_ciphertext.clone(), aes_ciphertext.clone());

        let (rsa, aes) = ciphertext_data.get_components();
        assert_eq!(rsa, rsa_ciphertext);
        assert_eq!(aes, aes_ciphertext);
    }

    #[test]
    fn test_ciphertext_data_serialization() {
        let rsa_ciphertext = RsaCiphertext::new(vec![1, 2, 3, 4]);
        let aes_ciphertext = AesCiphertext::new(
            false,
            vec![5, 6, 7, 8],
            Iv::new().unwrap(),
            vec![9, 10, 11, 12],
            [1; 16],
        );
        let ciphertext_data = CiphertextData::new(rsa_ciphertext.clone(), aes_ciphertext.clone());

        let serialized = serde_json::to_string(&ciphertext_data).unwrap();
        let deserialized: CiphertextData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.rsa_ciphertext, rsa_ciphertext);
        assert_eq!(deserialized.aes_ciphertext, aes_ciphertext);
    }
}
