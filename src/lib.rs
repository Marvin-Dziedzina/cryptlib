/// CryptLib is a library that provides RSA and AES encryption and decryption functions, as well as SHA hash functions.
///
/// # Modules
/// - `aes`: Contains AES encryption and decryption functionalities.
/// - `rsa`: Contains RSA encryption, decryption, and signing functionalities.
/// - `bits`: Utility module for handling bit operations.
/// - `error`: Defines custom error types for the library.
/// - `responses`: Defines structures for handling encrypted data.
///
/// # Structs
/// - `CryptLib`: Main structure that holds instances of RSA and AES encryption objects.
///
/// # Type Definitions
/// - `Sha256Hash`: Type alias for a 32-byte array representing a SHA256 hash.
/// - `Sha384Hash`: Type alias for a 48-byte array representing a SHA384 hash.
/// - `Sha512Hash`: Type alias for a 64-byte array representing a SHA512 hash.
///
/// # Methods
/// - `new(bits: Bits) -> Result<Self, CryptError>`: Creates a new instance of `CryptLib` with the specified RSA key size.
/// - `from_aes_key(bits: u32, aes_key: AesKey) -> Result<Self, CryptError>`: Creates a new instance of `CryptLib` from an existing AES key.
/// - `get_public_keys(&self) -> Result<PublicKey, CryptError>`: Retrieves the public keys for RSA encryption.
/// - `encrypt_composit(&self, receiver_public_key: &PublicKey, data: &[u8], aad: Vec<u8>) -> Result<CiphertextData, CryptError>`: Encrypts data using AES and encrypts the AES key using RSA.
/// - `decrypt_composit(&self, ciphertext: CiphertextData) -> Result<AesDecrypted, CryptError>`: Decrypts data that was encrypted using the `encrypt_composit` method.
/// - `sign(&self, data: &[u8]) -> Result<Signature, CryptError>`: Signs data using RSA.
/// - `verify(&self, public_key: &PublicKey, data: &[u8], signature: Signature) -> Result<bool, CryptError>`: Verifies the RSA signature of the data.
/// - `sha256(buf: &[u8]) -> Sha256Hash`: Creates a SHA256 hash from the input buffer.
/// - `sha384(buf: &[u8]) -> Sha384Hash`: Creates a SHA384 hash from the input buffer.
/// - `sha512(buf: &[u8]) -> Sha512Hash`: Creates a SHA512 hash from the input buffer.
///
/// # Tests
/// - `crypt_lib_encryption`: Tests the encryption and decryption functionality.
/// - `crypt_lib_signing`: Tests the signing and verification functionality.
/// - `crypt_lib_serde`: Tests serialization and deserialization of `CryptLib`.
/// - `sha256_test`: Tests the SHA256 hash function.
/// - `sha384_test`: Tests the SHA384 hash function.
/// - `sha512_test`: Tests the SHA512 hash function.
/// - `crypt_lib_encryption_different_key_sizes`: Tests encryption and decryption with different RSA key sizes.
/// - `crypt_lib_decryption_failure`: Tests decryption failure with tampered ciphertext.
/// - `crypt_lib_signing_verification_failure`: Tests verification failure with incorrect data.
pub mod aes;
pub mod rsa;
pub mod sha;

mod bits;
mod error;
mod responses;

pub use bits::Bits;
pub use error::CryptError;
pub use responses::CiphertextData;

use aes::{AesDecrypted, AesKey, AES};
use rsa::{PublicKey, Signature, RSA};
use serde::{Deserialize, Serialize};
use sha::Sha;

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptLib {
    pub rsa: RSA,
    pub aes: AES,
    pub sha: Sha,
}
/// CryptLib is a library that provides cryptographic functionalities including RSA and AES encryption,
/// digital signatures, and hashing. It supports creating instances with RSA key sizes and AES keys,
/// encrypting and decrypting data using a composite method (AES for data and RSA for AES key),
/// signing and verifying data, and generating SHA hashes.

impl CryptLib {
    pub fn new(bits: Bits) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits.to_bits())?,
            aes: AES::new()?,
            sha: Sha::new(),
        })
    }

    /// Create instance from aes key
    pub fn from_aes_key(bits: u32, aes_key: AesKey) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::from_key(aes_key),
            sha: Sha::new(),
        })
    }

    pub fn get_public_keys(&self) -> Result<PublicKey, CryptError> {
        self.rsa.get_public_keys()
    }

    /// Encrypt `data`. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composit meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    pub fn encrypt_composit(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
        aad: Vec<u8>,
    ) -> Result<CiphertextData, CryptError> {
        let aes_ciphertext = self.aes.encrypt(data, aad)?;
        let aes_key = self
            .rsa
            .encrypt(receiver_public_key, &self.aes.get_key().get_bytes())?;

        Ok(CiphertextData::new(aes_key, aes_ciphertext))
    }

    /// Decrypt `CiphertextData` composit.
    /// Composit meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    pub fn decrypt_composit(&self, ciphertext: CiphertextData) -> Result<AesDecrypted, CryptError> {
        let (rsa_ciphertext, aes_ciphertext) = ciphertext.get_components();

        let aes_key = AesKey::from_vec(&self.rsa.decrypt(rsa_ciphertext)?)?;

        self.aes.decrypt_with_key(aes_ciphertext, &aes_key)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        self.rsa.sign(data)
    }

    /// Verify that signature and data match
    pub fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        signature: Signature,
    ) -> Result<bool, CryptError> {
        self.rsa.verify(public_key, data, signature)
    }
}

#[cfg(test)]
mod crypt_lib_tests {
    use rsa::RsaCiphertext;

    use super::*;

    #[test]
    fn crypt_lib_encryption() {
        let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();

        let data = "Encrypted data!".as_bytes();
        let aad = "AAD data".as_bytes().to_vec();

        let ciphertext = crypt_lib
            .encrypt_composit(&crypt_lib.get_public_keys().unwrap(), data, aad.clone())
            .unwrap();

        let decrypted = crypt_lib.decrypt_composit(ciphertext).unwrap();

        let (data_dec, aad_dec) = decrypted.get_components();

        assert_eq!(data, data_dec);
        assert_eq!(aad, aad_dec);
    }

    #[test]
    fn crypt_lib_signing() {
        let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();

        let data = "Test".as_bytes();

        let signature = crypt_lib.sign(data).unwrap();

        let result = crypt_lib
            .verify(&crypt_lib.get_public_keys().unwrap(), data, signature)
            .unwrap();

        assert!(result);
    }

    #[test]
    fn crypt_lib_serde() {
        let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();

        let json = serde_json::to_string(&crypt_lib).unwrap();

        let _: CryptLib = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn crypt_lib_encryption_different_key_sizes() {
        let crypt_lib_2048 = CryptLib::new(Bits::Bits2048).unwrap();
        let crypt_lib_4096 = CryptLib::new(Bits::Bits4096).unwrap();

        let data = "Encrypted data!".as_bytes();
        let aad = "AAD data".as_bytes().to_vec();

        let ciphertext_2048 = crypt_lib_2048
            .encrypt_composit(
                &crypt_lib_2048.get_public_keys().unwrap(),
                data,
                aad.clone(),
            )
            .unwrap();
        let decrypted_2048 = crypt_lib_2048.decrypt_composit(ciphertext_2048).unwrap();
        let (data_dec_2048, aad_dec_2048) = decrypted_2048.get_components();
        assert_eq!(data, data_dec_2048);
        assert_eq!(aad, aad_dec_2048);

        let ciphertext_4096 = crypt_lib_4096
            .encrypt_composit(
                &crypt_lib_4096.get_public_keys().unwrap(),
                data,
                aad.clone(),
            )
            .unwrap();
        let decrypted_4096 = crypt_lib_4096.decrypt_composit(ciphertext_4096).unwrap();
        let (data_dec_4096, aad_dec_4096) = decrypted_4096.get_components();
        assert_eq!(data, data_dec_4096);
        assert_eq!(aad, aad_dec_4096);
    }

    #[test]
    fn crypt_lib_decryption_failure() {
        let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();

        let data = "Encrypted data!".as_bytes();
        let aad = "AAD data".as_bytes().to_vec();

        let ciphertext = crypt_lib
            .encrypt_composit(&crypt_lib.get_public_keys().unwrap(), data, aad.clone())
            .unwrap();

        // Tamper with the ciphertext
        let mut tampered_ciphertext = ciphertext.clone();
        let (rsa_cyphertext, aes_cypertext) = tampered_ciphertext.get_components();
        let mut rsa_cypherthext_bytes = rsa_cyphertext.get_component();
        rsa_cypherthext_bytes.push(5);
        tampered_ciphertext =
            CiphertextData::new(RsaCiphertext::new(rsa_cypherthext_bytes), aes_cypertext);

        let result = crypt_lib.decrypt_composit(tampered_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn crypt_lib_signing_verification_failure() {
        let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();

        let data = "Test".as_bytes();
        let wrong_data = "Wrong Test".as_bytes();

        let signature = crypt_lib.sign(data).unwrap();

        let result = crypt_lib
            .verify(&crypt_lib.get_public_keys().unwrap(), wrong_data, signature)
            .unwrap();

        assert!(!result);
    }
}
