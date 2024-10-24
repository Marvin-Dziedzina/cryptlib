/// Stores `data` and `aad`.
pub struct AesDecrypted {
    pub is_stream: bool,
    pub data: Vec<u8>,
    pub aad: Vec<u8>,
}
impl AesDecrypted {
    /// Create a new `AesDecrypted` instance.
    pub fn new(is_stream: bool, data: Vec<u8>, aad: Vec<u8>) -> Self {
        Self {
            is_stream,
            data,
            aad,
        }
    }

    /// Get components as tuple (data, aad).
    pub fn get_components(self) -> (Vec<u8>, Vec<u8>) {
        (self.data, self.aad)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_decrypted_new() {
        let data = vec![1, 2, 3, 4];
        let aad = vec![5, 6, 7, 8];
        let decrypted = AesDecrypted::new(false, data.clone(), aad.clone());
        assert_eq!(decrypted.data, data);
        assert_eq!(decrypted.aad, aad);
    }

    #[test]
    fn test_aes_decrypted_get_components() {
        let data = vec![1, 2, 3, 4];
        let aad = vec![5, 6, 7, 8];
        let decrypted = AesDecrypted::new(false, data.clone(), aad.clone());
        let (d, a) = decrypted.get_components();
        assert_eq!(d, data);
        assert_eq!(a, aad);
    }

    #[test]
    fn test_aes_decrypted_empty() {
        let data = vec![];
        let aad = vec![];
        let decrypted = AesDecrypted::new(false, data.clone(), aad.clone());
        assert_eq!(decrypted.data, data);
        assert_eq!(decrypted.aad, aad);
    }

    #[test]
    fn test_aes_decrypted_large_data() {
        let data = vec![0; 1024];
        let aad = vec![1; 1024];
        let decrypted = AesDecrypted::new(false, data.clone(), aad.clone());
        assert_eq!(decrypted.data, data);
        assert_eq!(decrypted.aad, aad);
    }
}
