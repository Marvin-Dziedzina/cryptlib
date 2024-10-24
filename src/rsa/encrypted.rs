use serde::{Deserialize, Serialize};

/// Stores a ciphertext
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RsaCiphertext {
    ciphertext: Vec<u8>,
}
impl RsaCiphertext {
    /// Create a new instance of `RsaCiphertext`
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Consumes self and returns the ciphertext
    pub fn get_component(self) -> Vec<u8> {
        self.ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_rsa_ciphertext() {
        let data = vec![1, 2, 3, 4, 5];
        let ciphertext = RsaCiphertext::new(data.clone());
        assert_eq!(ciphertext.ciphertext, data);
    }

    #[test]
    fn test_get_component() {
        let data = vec![1, 2, 3, 4, 5];
        let ciphertext = RsaCiphertext::new(data.clone());
        let extracted_data = ciphertext.get_component();
        assert_eq!(extracted_data, data);
    }

    #[test]
    fn test_clone_rsa_ciphertext() {
        let data = vec![1, 2, 3, 4, 5];
        let ciphertext = RsaCiphertext::new(data.clone());
        let cloned_ciphertext = ciphertext.clone();
        assert_eq!(cloned_ciphertext.ciphertext, data);
    }

    #[test]
    fn test_serialize_rsa_ciphertext() {
        let data = vec![1, 2, 3, 4, 5];
        let ciphertext = RsaCiphertext::new(data.clone());
        let serialized = serde_json::to_string(&ciphertext).unwrap();
        let expected = r#"{"ciphertext":[1,2,3,4,5]}"#.to_string();
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_deserialize_rsa_ciphertext() {
        let data = vec![1, 2, 3, 4, 5];
        let json_data = r#"{"ciphertext":[1,2,3,4,5]}"#;
        let deserialized: RsaCiphertext = serde_json::from_str(json_data).unwrap();
        assert_eq!(deserialized.ciphertext, data);
    }
}
