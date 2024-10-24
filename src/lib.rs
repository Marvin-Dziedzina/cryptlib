//! # CryptLib
//!
//! CryptLib is a simple cryptographic library that provides functionalities for RSA and AES encryption and decryption, as well as SHA hash functions. The library supports:
//!
//! - Creating instances with various RSA key sizes.
//! - Encrypting and decrypting data using a composite method, where data is encrypted with AES and the AES key is encrypted with RSA.
//! - Signing and verifying data using RSA digital signatures.
//! - Generating SHA hashes for data integrity and verification.
//!
//! ## Features
//!
//! - **RSA Encryption/Decryption**: Securely encrypt and decrypt data using RSA keys of different sizes.
//! - **AES Encryption/Decryption**: Efficiently encrypt and decrypt data using AES keys.
//! - **Composite Encryption**: Combine AES and RSA encryption to securely transmit data and keys.
//! - **Digital Signatures**: Sign data to ensure authenticity and verify signatures to confirm data integrity.
//! - **SHA Hashing**: Generate SHA hashes for data integrity checks.
//!
//! ## Modules
//!
//! - `rsa`: RSA encryption, decryption, and digital signature functionalities.
//! - `aes`: AES encryption and decryption functionalities.
//! - `sha`: SHA hashing functionalities.
//! - `bits`: Utility module for handling RSA key sizes.
//! - `error`: Error handling for cryptographic operations.
//! - `responses`: Structures for handling encrypted data and responses.
//!
//! ## Usage
//!
//! To use CryptLib, create an instance with the desired RSA key size and AES key, and then use the provided methods to encrypt, decrypt, sign, verify, and hash data.
//!
//! You can also use the different methods seperately by creating an instance of the desired module. CryptLib is a wrapper around the different functionalities and provides a more convenient way to use them together.
//!
//! Example usage of the composite encryption method:
//! ```rust
//! use cryptlib::{CryptLib, rsa::Bits};
//!
//! let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();
//! let data = b"Sensitive data";
//! let aad = b"Additional authenticated data. This data is not encrypted but it is safe from tampering.";
//!
//! // Encrypt data
//! let public_key = crypt_lib.get_public_keys().unwrap();
//! let ciphertext = crypt_lib.encrypt_composite(&public_key, data, aad).unwrap();
//!
//! // Decrypt data
//! let decrypted_data = crypt_lib.decrypt_composite(ciphertext).unwrap();
//! ```
//!
//! Example usage of signatures:
//! ```rust
//! use cryptlib::{CryptLib, rsa::Bits};
//!
//! let crypt_lib = CryptLib::new(Bits::Bits2048).unwrap();
//! let public_key = crypt_lib.get_public_keys().unwrap();
//! let data = b"Data to sign";
//!
//! // Sign data
//! let signature = crypt_lib.sign(data).unwrap();
//!
//! // Verify signature
//! let is_valid = crypt_lib.verify(&public_key, data, signature).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## Testing
//!
//! The library includes comprehensive tests to ensure the correctness of encryption, decryption, signing, and verification functionalities. The tests cover different RSA key sizes, serialization and deserialization, and error handling for tampered data and incorrect signatures.

pub mod aes;
pub mod hash;
pub mod rsa;

mod error;
mod responses;

use std::io::{Read, Write};

pub use error::CryptError;
pub use responses::CiphertextData;

use aes::{AesDecrypted, AesKey, AES};
use rsa::{Bits, PublicKey, Signature, RSA};
use serde::{Deserialize, Serialize};

/// CryptLib is a library that provides cryptographic functionalities including RSA and AES encryption,
/// digital signatures, and hashing. It supports creating instances with RSA key sizes and AES keys,
/// encrypting and decrypting data using a composite method (AES for data and RSA for AES key),
/// signing and verifying data, and generating SHA hashes.
#[derive(Debug, Serialize, Deserialize)]
pub struct CryptLib {
    pub rsa: RSA,
    pub aes: AES,
}
impl CryptLib {
    /// Create a new instance with RSA key size.
    pub fn new(bits: Bits) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::new()?,
        })
    }

    /// Create instance from aes key.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the RSA key is invalid.
    pub fn from_aes_key(bits: Bits, aes_key: AesKey) -> Result<Self, CryptError> {
        Ok(Self {
            rsa: RSA::new(bits)?,
            aes: AES::from_key(aes_key),
        })
    }

    pub fn get_public_keys(&self) -> Result<PublicKey, CryptError> {
        self.rsa.get_public_keys()
    }

    /// Encrypt `data`. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the encryption fails.
    pub fn encrypt_composite(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        self.encrypt_composite_with_aes_key(receiver_public_key, self.aes.get_key(), data, aad)
    }

    /// Encrypt `data` with AES key. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the encryption fails.
    pub fn encrypt_composite_with_aes_key(
        &self,
        receiver_public_key: &PublicKey,
        aes_key: &AesKey,
        data: &[u8],
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        let aes_ciphertext = self.aes.encrypt_with_key(data, aad, aes_key)?;
        let encrypted_aes_key = self
            .rsa
            .encrypt(receiver_public_key, &self.aes.get_key().get_bytes())?;

        Ok(CiphertextData::new(encrypted_aes_key, aes_ciphertext))
    }

    /// Decrypt a `CiphertextData` composite stream.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the encryption fails.
    pub fn encrypt_composite_stream<R: Read, W: Write>(
        &self,
        receiver_public_key: &PublicKey,
        reader: R,
        writer: W,
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        self.encrypt_composite_stream_with_aes_key(
            receiver_public_key,
            self.aes.get_key(),
            reader,
            writer,
            aad,
        )
    }

    /// Encrypt a stream. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the encryption fails.
    pub fn encrypt_composite_stream_with_aes_key<R: Read, W: Write>(
        &self,
        receiver_public_key: &PublicKey,
        aes_key: &AesKey,
        reader: R,
        writer: W,
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        let (_, aes_ciphertext) = self
            .aes
            .encrypt_stream_with_key(reader, writer, aes_key, aad)?;
        let encrypted_aes_key = self
            .rsa
            .encrypt(receiver_public_key, &self.aes.get_key().get_bytes())?;

        Ok(CiphertextData::new(encrypted_aes_key, aes_ciphertext))
    }

    /// Decrypt `CiphertextData` composite.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the decryption fails. This could mean that the data was tampered with.
    pub fn decrypt_composite(
        &self,
        ciphertext: CiphertextData,
    ) -> Result<AesDecrypted, CryptError> {
        let (rsa_ciphertext, aes_ciphertext) = ciphertext.get_components();

        let aes_key = AesKey::from_vec(&self.rsa.decrypt(rsa_ciphertext)?)?;

        self.aes.decrypt_with_key(aes_ciphertext, &aes_key)
    }

    /// Decrypt a stream. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the decryption fails. This could mean that the data was tampered with.
    pub fn decrypt_composite_stream<R: Read, W: Write>(
        &self,
        ciphertext: CiphertextData,
        reader: R,
        writer: W,
    ) -> Result<(usize, AesDecrypted), CryptError> {
        let (rsa_ciphertext, aes_ciphertext) = ciphertext.get_components();

        let aes_key = AesKey::from_vec(&self.rsa.decrypt(rsa_ciphertext)?)?;

        self.aes
            .decrypt_stream_with_key(reader, writer, &aes_key, aes_ciphertext)
    }

    /// Sign data.
    /// Returns a signature.
    /// This data can be verified with the public key and the signature.
    /// The signature should be kept with the data to verify it later or somewhere else.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        self.rsa.sign(data)
    }

    /// Verify that signature and data match with the public key of the signer.
    /// Returns a boolean indicating if the signature is valid.
    ///
    /// # Errors
    ///
    /// Returns a CryptError if the verification fails. This could mean that the data was tampered with.
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
            .encrypt_composite(&crypt_lib.get_public_keys().unwrap(), data, &aad)
            .unwrap();

        let decrypted = crypt_lib.decrypt_composite(ciphertext).unwrap();

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
            .encrypt_composite(&crypt_lib_2048.get_public_keys().unwrap(), data, &aad)
            .unwrap();
        let decrypted_2048 = crypt_lib_2048.decrypt_composite(ciphertext_2048).unwrap();
        let (data_dec_2048, aad_dec_2048) = decrypted_2048.get_components();
        assert_eq!(data, data_dec_2048);
        assert_eq!(aad, aad_dec_2048);

        let ciphertext_4096 = crypt_lib_4096
            .encrypt_composite(&crypt_lib_4096.get_public_keys().unwrap(), data, &aad)
            .unwrap();
        let decrypted_4096 = crypt_lib_4096.decrypt_composite(ciphertext_4096).unwrap();
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
            .encrypt_composite(&crypt_lib.get_public_keys().unwrap(), data, &aad)
            .unwrap();

        // Tamper with the ciphertext
        let mut tampered_ciphertext = ciphertext.clone();
        let (rsa_cyphertext, aes_cypertext) = tampered_ciphertext.get_components();
        let mut rsa_cypherthext_bytes = rsa_cyphertext.get_component();
        rsa_cypherthext_bytes.push(5);
        tampered_ciphertext =
            CiphertextData::new(RsaCiphertext::new(rsa_cypherthext_bytes), aes_cypertext);

        let result = crypt_lib.decrypt_composite(tampered_ciphertext);
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
