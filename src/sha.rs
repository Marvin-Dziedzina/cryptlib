use std::io::Read;

use openssl::sha;
use serde::{Deserialize, Serialize};

mod hashes;

pub use hashes::{Hash, Hasher};

use crate::CryptError;

/// Sha is a struct that provides SHA hashing functionalities.
/// It supports creating SHA hashes from buffers and streams.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Sha {}
impl Sha {
    /// Create a SHA hash from buf.
    pub fn sha(buf: &[u8], hash_type: Hasher) -> Hash {
        match hash_type {
            Hasher::Sha1 => Hash::Sha1(sha::sha1(buf)),
            Hasher::Sha224 => Hash::Sha224(sha::sha224(buf)),
            Hasher::Sha256 => Hash::Sha256(sha::sha256(buf)),
            Hasher::Sha384 => Hash::Sha384(sha::sha384(buf)),
            Hasher::Sha512 => Hash::Sha512(sha::sha512(buf)),
        }
    }

    /// Verify a SHA hash.
    /// This function will return true if the hash is valid, otherwise false.
    /// This method is useful for verifying the integrity of a file but **is not secure**.
    pub fn verify_sha(buf: &[u8], hash: Hash) -> bool {
        match hash {
            Hash::Sha1(h) => h == sha::sha1(buf),
            Hash::Sha224(h) => h == sha::sha224(buf),
            Hash::Sha256(h) => h == sha::sha256(buf),
            Hash::Sha384(h) => h == sha::sha384(buf),
            Hash::Sha512(h) => h == sha::sha512(buf),
        }
    }

    /// Create a SHA1 from stream.
    ///
    /// # Errors:
    ///
    /// This function will return an error if there was an error reading from the stream.
    pub fn sha1_stream<R: Read>(mut reader: R) -> Result<Hash, CryptError> {
        let mut hasher = sha::Sha1::new();

        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            }

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finish();

        Ok(Hash::Sha1(hash))
    }

    /// Create a SHA224 from stream.
    ///
    /// # Errors:
    ///
    /// This function will return an error if there was an error reading from the stream.
    pub fn sha224_stream<R: Read>(mut reader: R) -> Result<Hash, CryptError> {
        let mut hasher = sha::Sha224::new();

        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            }

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finish();

        Ok(Hash::Sha224(hash))
    }

    /// Create a SHA256 from stream.
    ///
    /// # Errors:
    ///
    /// This function will return an error if there was an error reading from the stream.
    pub fn sha256_stream<R: Read>(mut reader: R) -> Result<Hash, CryptError> {
        let mut hasher = sha::Sha256::new();

        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            }

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finish();

        Ok(Hash::Sha256(hash))
    }

    /// Create a SHA384 from stream.
    ///
    /// # Errors:
    ///
    /// This function will return an error if there was an error reading from the stream.
    pub fn sha384_stream<R: Read>(mut reader: R) -> Result<Hash, CryptError> {
        let mut hasher = sha::Sha384::new();

        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            }

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finish();

        Ok(Hash::Sha384(hash))
    }

    /// Create a SHA512 from stream.
    ///
    /// # Errors:
    ///
    /// This function will return an error if there was an error reading from the stream.
    pub fn sha512_stream<R: Read>(mut reader: R) -> Result<Hash, CryptError> {
        let mut hasher = sha::Sha512::new();

        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            }

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finish();

        Ok(Hash::Sha512(hash))
    }

    /// Verify a SHA hash from a stream.
    /// This function will return true if the hash is valid, otherwise false.
    ///
    /// # Errors:
    ///
    /// This function will return an error if the hashing process fails or if the hash lenght is invalid.
    pub fn verify_sha_stream<R: Read>(reader: R, hash: Hash) -> Result<bool, CryptError> {
        let is_equal = match hash {
            Hash::Sha1(h) => h == Sha::sha1_stream(reader)?.get_value(),
            Hash::Sha224(h) => h == Sha::sha224_stream(reader)?.get_value(),
            Hash::Sha256(h) => h == Sha::sha256_stream(reader)?.get_value(),
            Hash::Sha384(h) => h == Sha::sha384_stream(reader)?.get_value(),
            Hash::Sha512(h) => h == Sha::sha512_stream(reader)?.get_value(),
        };

        Ok(is_equal)
    }
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use crate::sha::{Hash, Hasher, Sha};

    #[test]
    fn sha1_test() {
        let buf = b"Sha1 Test";

        let hash = Sha::sha(buf, Hasher::Sha1);

        assert_eq!(
            hash.get_value(),
            [
                110, 242, 87, 196, 203, 33, 107, 220, 26, 220, 121, 215, 19, 221, 130, 135, 215,
                38, 95, 20
            ]
        );

        let is_valid = Sha::verify_sha(buf, hash);

        assert!(is_valid);
    }

    #[test]
    fn sha224_test() {
        let buf = b"Sha224 Test";

        let hash = Sha::sha(buf, Hasher::Sha224);

        assert_eq!(
            hash.get_value(),
            [
                10, 199, 37, 128, 197, 245, 34, 137, 54, 236, 196, 125, 35, 183, 135, 37, 19, 97,
                201, 81, 220, 59, 45, 229, 74, 130, 162, 90
            ]
        );

        let is_valid = Sha::verify_sha(buf, hash);

        assert!(is_valid);
    }

    #[test]
    fn sha256_test() {
        let buf = b"Sha256 Test";

        let hash = Sha::sha(buf, Hasher::Sha256);

        assert_eq!(
            hash.get_value(),
            [
                // This array represents the sha256 hash of "Sha256 Test"
                166, 60, 82, 147, 46, 231, 78, 240, 20, 236, 61, 240, 28, 106, 175, 103, 46, 102,
                174, 38, 19, 220, 90, 2, 210, 253, 126, 140, 69, 27, 30, 112
            ]
        );

        let is_valid = Sha::verify_sha(buf, hash);

        assert!(is_valid);
    }

    #[test]
    fn sha384_test() {
        let buf = b"Sha384 Test";

        let hash = Sha::sha(buf, Hasher::Sha384);

        assert_eq!(
            hash.get_value(),
            [
                // This array represents the sha384 hash of "Sha384 Test"
                47, 241, 54, 247, 112, 182, 93, 137, 55, 154, 105, 32, 124, 5, 188, 118, 209, 252,
                88, 182, 216, 215, 95, 108, 209, 71, 56, 103, 18, 35, 78, 124, 245, 167, 59, 124,
                172, 86, 207, 226, 195, 193, 150, 247, 213, 26, 143, 201
            ]
        );

        let is_valid = Sha::verify_sha(buf, hash);

        assert!(is_valid);
    }

    #[test]
    fn sha512_test() {
        let buf = b"Sha512 Test";

        let hash = Sha::sha(buf, Hasher::Sha512);

        assert_eq!(
            hash.get_value(),
            [
                // This array represents the sha512 hash of "Sha512 Test"
                111, 166, 149, 142, 226, 122, 152, 89, 111, 143, 201, 158, 153, 177, 26, 248, 116,
                141, 208, 158, 128, 166, 150, 92, 143, 139, 250, 45, 189, 105, 60, 249, 68, 83, 92,
                15, 186, 27, 119, 102, 170, 114, 209, 114, 171, 18, 58, 227, 218, 232, 114, 101,
                17, 120, 240, 45, 253, 244, 44, 41, 176, 119, 162, 220
            ]
        );

        let is_valid = Sha::verify_sha(buf, hash);

        assert!(is_valid);
    }

    #[test]
    fn sha1_stream_test() {
        let buf = b"Sha1 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = Sha::sha1_stream(reader).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                221, 40, 122, 213, 138, 245, 31, 247, 186, 57, 61, 208, 199, 75, 81, 74, 241, 29,
                184, 171
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = Sha::verify_sha_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha224_stream_test() {
        let buf = b"Sha224 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = Sha::sha224_stream(reader).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                132, 218, 223, 128, 127, 158, 130, 199, 17, 219, 189, 202, 33, 5, 171, 176, 242,
                152, 22, 117, 93, 161, 188, 128, 216, 213, 172, 200
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = Sha::verify_sha_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha256_stream_test() {
        let buf = b"Sha256 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = Sha::sha256_stream(reader).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                60, 248, 124, 82, 251, 175, 47, 177, 53, 166, 254, 127, 197, 18, 116, 0, 78, 97,
                179, 144, 123, 163, 45, 36, 106, 181, 33, 162, 82, 17, 153, 126
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = Sha::verify_sha_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha384_stream_test() {
        let buf = b"Sha384 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = Sha::sha384_stream(reader).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                81, 46, 86, 32, 20, 155, 76, 72, 182, 44, 164, 55, 97, 196, 93, 239, 215, 103, 100,
                98, 86, 5, 190, 242, 230, 153, 223, 236, 244, 124, 38, 244, 33, 196, 248, 82, 228,
                199, 61, 59, 203, 141, 107, 173, 177, 72, 106, 229
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = Sha::verify_sha_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha512_stream_test() {
        let buf = b"Sha512 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = Sha::sha512_stream(reader).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                226, 180, 148, 160, 35, 242, 120, 142, 51, 85, 47, 102, 144, 190, 22, 141, 152,
                106, 188, 185, 64, 164, 236, 202, 59, 0, 192, 240, 153, 17, 42, 93, 146, 251, 207,
                172, 14, 8, 54, 117, 237, 49, 45, 166, 180, 85, 235, 35, 182, 13, 211, 185, 156,
                197, 19, 87, 129, 10, 224, 106, 137, 75, 56, 90
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = Sha::verify_sha_stream(reader, hash).unwrap();

        assert!(is_valid);
    }
}
