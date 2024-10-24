/// Represents all the possible SHA hashers
/// The higher the number, the more secure the hash is but the slower the processing.
pub enum Hasher {
    /// **Should not be used for security critical tasks!** Theoretical attacks have been known since 2005. In 2011 NIST deprecated the use of SHA1.
    Sha1,
    /// This hasher is rarely used. But is still considered secure.
    Sha224,
    /// This hasher is the most common one. It is considered secure.
    Sha256,
    /// This hasher is considered secure.
    Sha384,
    /// This hasher is considered secure.
    Sha512,
}

/// Represents all the possible SHA hashes.
pub enum Hash {
    Sha1([u8; 20]),
    Sha224([u8; 28]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}
impl Hash {
    /// Get the hash type.
    pub fn get_hasher(&self) -> Hasher {
        match self {
            Hash::Sha1(_) => Hasher::Sha1,
            Hash::Sha224(_) => Hasher::Sha224,
            Hash::Sha256(_) => Hasher::Sha256,
            Hash::Sha384(_) => Hasher::Sha384,
            Hash::Sha512(_) => Hasher::Sha512,
        }
    }

    /// Get the hash value.
    pub fn get_value(&self) -> &[u8] {
        match self {
            Hash::Sha1(value) => value,
            Hash::Sha224(value) => value,
            Hash::Sha256(value) => value,
            Hash::Sha384(value) => value,
            Hash::Sha512(value) => value,
        }
    }
}
