//! The `sha` module provides SHA hashing functionalities.
//! It supports creating SHA hashes from buffers and streams.
//! The module supports SHA1, SHA224, SHA256, SHA384, and SHA512 hashing algorithms.
//! The module also provides functions to verify the integrity of the data using SHA hashes.
//! The module uses the `openssl` crate to provide the hashing functionalities.
//!
//! # Example
//!
//! Create a SHA hash from a buffer:
//! ```rust
//! use cryptlib::hash::{self, HashType};
//!
//! let buf = b"Hello, World!";
//!
//! let hash = hash::hasher(buf, HashType::Sha256).unwrap();
//!
//! let is_valid = hash::verify_hash(buf, hash).unwrap();
//!
//! assert!(is_valid);
//! ```
//!
//! Create a SHA hash from a stream:
//! ```rust
//! use std::io::BufReader;
//! use cryptlib::hash::{self, HashType};
//!
//! let buf = b"Hello, World!";
//! let reader = BufReader::new(&buf[..]);
//!
//! let hash = hash::hasher_stream(reader, HashType::Sha256).unwrap();
//!
//! let reader = BufReader::new(&buf[..]);
//! let is_valid = hash::verify_hash_stream(reader, hash).unwrap();
//!
//! assert!(is_valid);
//! ```

use std::io::Read;

use openssl::{hash::Hasher, memcmp};

mod hashes;

pub use hashes::{Hash, HashType};

use crate::CryptError;

/// Create a SHA hash from bytes.
pub fn hasher(buf: &[u8], hash_type: HashType) -> Result<Hash, CryptError> {
    let message_digest = hash_type.get_message_digest();

    let mut hasher = Hasher::new(message_digest).map_err(CryptError::HashError)?;

    hasher.update(buf).map_err(CryptError::HashError)?;

    let digest_bytes = hasher.finish().map_err(CryptError::HashError)?;

    Hash::from_digest_bytes(digest_bytes, hash_type)
}

/// Verify a SHA hash.
/// This function will return true if the hash is valid, otherwise false.
/// This method is useful for verifying the integrity of data but **is not secure**.
pub fn verify_hash(buf: &[u8], hash: Hash) -> Result<bool, CryptError> {
    let is_valid = match hash {
        Hash::Md5(h) => memcmp::eq(&h, hasher(buf, HashType::Md5)?.get_value()),
        Hash::Sha224(h) => memcmp::eq(&h, hasher(buf, HashType::Sha224)?.get_value()),
        Hash::Sha256(h) => memcmp::eq(&h, hasher(buf, HashType::Sha256)?.get_value()),
        Hash::Sha384(h) => memcmp::eq(&h, hasher(buf, HashType::Sha384)?.get_value()),
        Hash::Sha512(h) => memcmp::eq(&h, hasher(buf, HashType::Sha512)?.get_value()),
        Hash::Sha3_224(h) => memcmp::eq(&h, hasher(buf, HashType::Sha3_224)?.get_value()),
        Hash::Sha3_256(h) => memcmp::eq(&h, hasher(buf, HashType::Sha3_256)?.get_value()),
        Hash::Sha3_384(h) => memcmp::eq(&h, hasher(buf, HashType::Sha3_384)?.get_value()),
        Hash::Sha3_512(h) => memcmp::eq(&h, hasher(buf, HashType::Sha3_512)?.get_value()),
    };

    Ok(is_valid)
}

/// Create a SHA hash from a stream.
/// This function reads the stream in chunks and creates a hash.
/// It is useful for hashing large files.
///
/// # Errors
///
/// This function will return an error if there was an error reading from the stream.
/// This function will return an error if the hashing process fails.
pub fn hasher_stream<R: Read>(mut reader: R, hash_type: HashType) -> Result<Hash, CryptError> {
    let message_digest = hash_type.get_message_digest();

    let mut hasher = Hasher::new(message_digest).map_err(CryptError::HashError)?;

    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]).map_err(CryptError::HashError)?;
    }

    let digest_bytes = hasher.finish().map_err(CryptError::HashError)?;

    Hash::from_digest_bytes(digest_bytes, hash_type)
}

/// Verify a SHA hash from a stream.
/// This function will return true if the hash is valid, otherwise false.
/// It is useful for verifying the integrity of data but **is not secure**.
///
/// # Errors
///
/// This function will return an error if the hashing process fails or if the hash lenght is invalid.
pub fn verify_hash_stream<R: Read>(reader: R, hash: Hash) -> Result<bool, CryptError> {
    let is_equal = match hash {
        Hash::Md5(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Md5)?.get_value()),
        Hash::Sha224(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha224)?.get_value()),
        Hash::Sha256(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha256)?.get_value()),
        Hash::Sha384(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha384)?.get_value()),
        Hash::Sha512(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha512)?.get_value()),
        Hash::Sha3_224(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha3_224)?.get_value()),
        Hash::Sha3_256(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha3_256)?.get_value()),
        Hash::Sha3_384(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha3_384)?.get_value()),
        Hash::Sha3_512(h) => memcmp::eq(&h, hasher_stream(reader, HashType::Sha3_512)?.get_value()),
    };

    Ok(is_equal)
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use crate::hash::{self, HashType};

    #[test]
    fn md5_test() {
        let buf = b"Md5 Test";

        let hash = hash::hasher(buf, HashType::Md5).unwrap();

        assert_eq!(
            hash.get_value(),
            [9, 246, 25, 144, 223, 231, 163, 45, 234, 97, 70, 48, 12, 0, 63, 105]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha224_test() {
        let buf = b"Sha224 Test";

        let hash = hash::hasher(buf, HashType::Sha224).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                10, 199, 37, 128, 197, 245, 34, 137, 54, 236, 196, 125, 35, 183, 135, 37, 19, 97,
                201, 81, 220, 59, 45, 229, 74, 130, 162, 90
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha256_test() {
        let buf = b"Sha256 Test";

        let hash = hash::hasher(buf, HashType::Sha256).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                // This array represents the sha256 hash of "Sha256 Test"
                166, 60, 82, 147, 46, 231, 78, 240, 20, 236, 61, 240, 28, 106, 175, 103, 46, 102,
                174, 38, 19, 220, 90, 2, 210, 253, 126, 140, 69, 27, 30, 112
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha384_test() {
        let buf = b"Sha384 Test";

        let hash = hash::hasher(buf, HashType::Sha384).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                // This array represents the sha384 hash of "Sha384 Test"
                47, 241, 54, 247, 112, 182, 93, 137, 55, 154, 105, 32, 124, 5, 188, 118, 209, 252,
                88, 182, 216, 215, 95, 108, 209, 71, 56, 103, 18, 35, 78, 124, 245, 167, 59, 124,
                172, 86, 207, 226, 195, 193, 150, 247, 213, 26, 143, 201
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha512_test() {
        let buf = b"Sha512 Test";

        let hash = hash::hasher(buf, HashType::Sha512).unwrap();

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

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_224_test() {
        let buf = b"Sha3_224 Test";

        let hash = hash::hasher(buf, HashType::Sha3_224).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                120, 11, 29, 20, 202, 213, 159, 203, 131, 216, 85, 61, 58, 140, 150, 60, 183, 166,
                210, 81, 174, 96, 126, 79, 239, 84, 76, 229
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_256_test() {
        let buf = b"Sha3_256 Test";

        let hash = hash::hasher(buf, HashType::Sha3_256).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                57, 138, 76, 249, 10, 68, 250, 59, 123, 107, 55, 236, 89, 68, 174, 7, 75, 221, 62,
                63, 86, 238, 8, 157, 151, 184, 101, 201, 114, 228, 27, 30
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_384_test() {
        let buf = b"Sha3_384 Test";

        let hash = hash::hasher(buf, HashType::Sha3_384).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                187, 80, 62, 76, 248, 147, 185, 43, 70, 200, 82, 132, 72, 74, 31, 91, 143, 55, 85,
                32, 222, 169, 51, 218, 214, 86, 158, 158, 118, 53, 98, 47, 101, 21, 137, 252, 248,
                5, 171, 236, 197, 147, 242, 205, 240, 203, 34, 29
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_512_test() {
        let buf = b"Sha3_512 Test";

        let hash = hash::hasher(buf, HashType::Sha3_512).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                41, 195, 201, 144, 67, 177, 242, 91, 71, 33, 227, 123, 22, 95, 88, 14, 63, 243,
                108, 162, 5, 133, 183, 16, 197, 105, 247, 157, 28, 51, 12, 119, 4, 241, 115, 90,
                92, 1, 12, 75, 238, 36, 6, 162, 50, 213, 108, 135, 27, 24, 74, 187, 222, 243, 112,
                145, 169, 193, 89, 216, 30, 17, 20, 237
            ]
        );

        let is_valid = hash::verify_hash(buf, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn md5_stream_test() {
        let buf = b"Md5 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Md5).unwrap();

        assert_eq!(
            hash.get_value(),
            [69, 58, 110, 225, 44, 79, 126, 37, 122, 109, 83, 84, 27, 175, 229, 196]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha224_stream_test() {
        let buf = b"Sha224 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha224).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                132, 218, 223, 128, 127, 158, 130, 199, 17, 219, 189, 202, 33, 5, 171, 176, 242,
                152, 22, 117, 93, 161, 188, 128, 216, 213, 172, 200
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha256_stream_test() {
        let buf = b"Sha256 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha256).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                60, 248, 124, 82, 251, 175, 47, 177, 53, 166, 254, 127, 197, 18, 116, 0, 78, 97,
                179, 144, 123, 163, 45, 36, 106, 181, 33, 162, 82, 17, 153, 126
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha384_stream_test() {
        let buf = b"Sha384 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha384).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                81, 46, 86, 32, 20, 155, 76, 72, 182, 44, 164, 55, 97, 196, 93, 239, 215, 103, 100,
                98, 86, 5, 190, 242, 230, 153, 223, 236, 244, 124, 38, 244, 33, 196, 248, 82, 228,
                199, 61, 59, 203, 141, 107, 173, 177, 72, 106, 229
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha512_stream_test() {
        let buf = b"Sha512 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha512).unwrap();

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
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_224_stream_test() {
        let buf = b"Sha3_224 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha3_224).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                248, 109, 34, 207, 138, 91, 141, 52, 98, 26, 225, 43, 27, 133, 129, 153, 35, 12,
                245, 101, 168, 19, 85, 183, 152, 234, 199, 208
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_256_stream_test() {
        let buf = b"Sha3_256 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha3_256).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                122, 98, 20, 2, 35, 153, 98, 17, 3, 163, 150, 121, 40, 201, 133, 251, 11, 104, 50,
                117, 156, 14, 108, 159, 215, 7, 225, 157, 224, 223, 95, 35
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_384_stream_test() {
        let buf = b"Sha3_384 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha3_384).unwrap();

        assert_eq!(
            hash.get_value(),
            [
                224, 232, 248, 170, 223, 184, 127, 151, 66, 208, 189, 243, 180, 38, 14, 149, 85,
                228, 198, 175, 115, 11, 155, 214, 238, 1, 185, 255, 169, 72, 241, 183, 70, 44, 204,
                166, 119, 230, 136, 106, 148, 187, 239, 97, 178, 158, 59, 238
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn sha3_512_stream_test() {
        let buf = b"Sha3_512 Stream Test";
        let reader = BufReader::new(&buf[..]);

        let hash = hash::hasher_stream(reader, HashType::Sha3_512).unwrap();
        println!("{:?}", hash.get_value());
        assert_eq!(
            hash.get_value(),
            [
                2, 123, 229, 65, 103, 125, 127, 206, 158, 240, 116, 66, 207, 251, 125, 89, 17, 253,
                153, 126, 61, 224, 99, 183, 13, 147, 27, 96, 229, 222, 136, 95, 232, 10, 219, 188,
                73, 188, 52, 247, 139, 85, 210, 48, 251, 92, 80, 115, 71, 204, 203, 105, 246, 2,
                147, 234, 35, 183, 247, 102, 138, 46, 107, 198
            ]
        );

        let reader = BufReader::new(&buf[..]);
        let is_valid = hash::verify_hash_stream(reader, hash).unwrap();

        assert!(is_valid);
    }
}
