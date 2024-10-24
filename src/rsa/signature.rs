use serde::{Deserialize, Serialize};

/// Stores a signature.
/// Is needed to verify the signed data.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    signature: Vec<u8>,
}
impl Signature {
    /// Create a new instance of `Signature`.
    pub fn new(signature: Vec<u8>) -> Self {
        Self { signature }
    }

    /// Consumes self and returns the signature.
    pub fn get_signature(self) -> Vec<u8> {
        self.signature
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let signature = Signature::new(data.clone());
        assert_eq!(signature.get_signature(), data);
    }

    #[test]
    fn test_signature_empty() {
        let data = vec![];
        let signature = Signature::new(data.clone());
        assert_eq!(signature.get_signature(), data);
    }

    #[test]
    fn test_signature_large_data() {
        let data = vec![0; 1024];
        let signature = Signature::new(data.clone());
        assert_eq!(signature.get_signature(), data);
    }

    #[test]
    fn test_signature_serialization() {
        let data = vec![1, 2, 3, 4, 5];
        let signature = Signature::new(data.clone());
        let serialized = serde_json::to_string(&signature).unwrap();
        let deserialized: Signature = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.get_signature(), data);
    }
}
