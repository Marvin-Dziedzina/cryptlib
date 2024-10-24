use serde::{Deserialize, Serialize};

use super::Iv;

/// Stores `AES` ciphertext.
/// `is_stream` is a flag that indicates if the ciphertext is a stream or block cipher.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AesCiphertext {
    pub is_stream: bool,
    pub ciphertext: Vec<u8>,
    pub iv: Iv,
    pub aad: Vec<u8>,
    pub tag: [u8; 16],
}
impl AesCiphertext {
    /// Create a new `AesCiphertext` instance.
    pub fn new(is_stream: bool, ciphertext: Vec<u8>, iv: Iv, aad: Vec<u8>, tag: [u8; 16]) -> Self {
        Self {
            is_stream,
            ciphertext,
            iv,
            aad,
            tag,
        }
    }

    /// Get components (is_stream, ciphertext, iv, aad, tag)
    pub fn get_components(self) -> (bool, Vec<u8>, [u8; 16], Vec<u8>, [u8; 16]) {
        (
            self.is_stream,
            self.ciphertext,
            *self.iv.get_bytes(),
            self.aad,
            self.tag,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ciphertext_creation() {
        let ciphertext = vec![1, 2, 3, 4];
        let iv = Iv::new().unwrap();
        let aad = vec![5, 6, 7, 8];
        let tag = [1; 16];

        let aes_ciphertext =
            AesCiphertext::new(false, ciphertext.clone(), iv.clone(), aad.clone(), tag);

        assert_eq!(aes_ciphertext.ciphertext, ciphertext);
        assert_eq!(aes_ciphertext.iv, iv);
        assert_eq!(aes_ciphertext.aad, aad);
        assert_eq!(aes_ciphertext.tag, tag);
    }

    #[test]
    fn test_get_components() {
        let ciphertext = vec![1, 2, 3, 4];
        let iv = Iv::new().unwrap();
        let aad = vec![5, 6, 7, 8];
        let tag = [1; 16];

        let aes_ciphertext =
            AesCiphertext::new(false, ciphertext.clone(), iv.clone(), aad.clone(), tag);
        let (s, c, i, a, t) = aes_ciphertext.get_components();

        assert_eq!(s, false);
        assert_eq!(c, ciphertext);
        assert_eq!(i, *iv.get_bytes());
        assert_eq!(a, aad);
        assert_eq!(t, tag);
    }

    #[test]
    fn test_serde_serialization() {
        let ciphertext = vec![1, 2, 3, 4];
        let iv = Iv::new().unwrap();
        let aad = vec![5, 6, 7, 8];
        let tag = [1; 16];

        let aes_ciphertext =
            AesCiphertext::new(false, ciphertext.clone(), iv.clone(), aad.clone(), tag);
        let serialized = serde_json::to_string(&aes_ciphertext).unwrap();
        let deserialized: AesCiphertext = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.ciphertext, ciphertext);
        assert_eq!(deserialized.iv, iv);
        assert_eq!(deserialized.aad, aad);
        assert_eq!(deserialized.tag, tag);
    }
}
