use openssl::hash::{DigestBytes, MessageDigest};

use crate::CryptError;

/// Represents all the possible SHA hashers
/// The higher the number, the more secure the hash is but the slower the processing.
pub enum HashType {
    /// **Should not be used for security critical tasks!** Attacks against the compression function have been known since 1996. In 2004 full collisions were found. Can be used for non critical tasks.
    Md5,
    /// This hasher is rarely used. But is still considered secure.
    Sha224,
    /// This hasher is the most common one. It is considered secure.
    Sha256,
    /// This hasher is considered secure.
    Sha384,
    /// This hasher is considered secure.
    Sha512,
    /// This hasher is considered secure. The sha3 family is considered more secure than the sha2 family.
    Sha3_224,
    /// This hasher is considered secure. The sha3 family is considered more secure than the sha2 family.
    Sha3_256,
    /// This hasher is considered secure. The sha3 family is considered more secure than the sha2 family.
    Sha3_384,
    /// This hasher is considered secure. The sha3 family is considered more secure than the sha2 family.
    Sha3_512,
}
impl HashType {
    pub fn get_message_digest(&self) -> MessageDigest {
        match self {
            HashType::Md5 => MessageDigest::md5(),
            HashType::Sha224 => MessageDigest::sha224(),
            HashType::Sha256 => MessageDigest::sha256(),
            HashType::Sha384 => MessageDigest::sha384(),
            HashType::Sha512 => MessageDigest::sha512(),
            HashType::Sha3_224 => MessageDigest::sha3_224(),
            HashType::Sha3_256 => MessageDigest::sha3_256(),
            HashType::Sha3_384 => MessageDigest::sha3_384(),
            HashType::Sha3_512 => MessageDigest::sha3_512(),
        }
    }
}

/// Represents all the possible SHA hashes.
pub enum Hash {
    Md5([u8; 16]),
    Sha224([u8; 28]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
    Sha3_224([u8; 28]),
    Sha3_256([u8; 32]),
    Sha3_384([u8; 48]),
    Sha3_512([u8; 64]),
}
impl Hash {
    /// Create a new instance of `Hash` from `DigestBytes`.
    pub fn from_digest_bytes(
        digest_bytes: DigestBytes,
        hash_type: HashType,
    ) -> Result<Self, CryptError> {
        let hash = match hash_type {
            HashType::Md5 => Hash::Md5(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha224 => Hash::Sha224(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha256 => Hash::Sha256(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha384 => Hash::Sha384(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha512 => Hash::Sha512(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha3_224 => Hash::Sha3_224(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha3_256 => Hash::Sha3_256(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha3_384 => Hash::Sha3_384(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
            HashType::Sha3_512 => Hash::Sha3_512(
                digest_bytes
                    .as_ref()
                    .try_into()
                    .map_err(CryptError::TryFromSliceError)?,
            ),
        };

        Ok(hash)
    }

    /// Get the hash type.
    pub fn get_hasher(&self) -> HashType {
        match self {
            Hash::Md5(_) => HashType::Md5,
            Hash::Sha224(_) => HashType::Sha224,
            Hash::Sha256(_) => HashType::Sha256,
            Hash::Sha384(_) => HashType::Sha384,
            Hash::Sha512(_) => HashType::Sha512,
            Hash::Sha3_224(_) => HashType::Sha3_224,
            Hash::Sha3_256(_) => HashType::Sha3_256,
            Hash::Sha3_384(_) => HashType::Sha3_384,
            Hash::Sha3_512(_) => HashType::Sha3_512,
        }
    }

    /// Get the hash value.
    pub fn get_value(&self) -> &[u8] {
        match self {
            Hash::Md5(value) => value,
            Hash::Sha224(value) => value,
            Hash::Sha256(value) => value,
            Hash::Sha384(value) => value,
            Hash::Sha512(value) => value,
            Hash::Sha3_224(value) => value,
            Hash::Sha3_256(value) => value,
            Hash::Sha3_384(value) => value,
            Hash::Sha3_512(value) => value,
        }
    }
}
