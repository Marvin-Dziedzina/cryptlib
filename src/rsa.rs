//! `rsa` is the module providing the `RSA` struct, which provides RSA encryption and signing functionalities.
//! It supports encrypting and decrypting data, and signing and verifying data.
//! It uses the `openssl` crate for the RSA functionalities.
//! The `RSA` struct can be serialized and deserialized using the `serde` crate.
//!
//! # Examples
//!
//! Encrypt and decrypt data:
//! ```rust
//! use cryptlib::rsa::{RSA, Bits};
//!
//! let data = b"Hello, World!";
//!
//! let rsa = RSA::new(Bits::Bits2048).unwrap();
//!
//! // Get own public key to send data to myself.
//! let public_key = rsa.get_public_keys().unwrap();
//!
//! // Encrypt data
//! let ciphertext = rsa.encrypt(&public_key, data).unwrap();
//!
//! // Decrypt data
//! let decrypted_data = rsa.decrypt(ciphertext).unwrap();
//!
//! assert_eq!(data.to_vec(), decrypted_data);
//! ```
//!
//! Sign and verify data:
//! ```rust
//! use cryptlib::rsa::{RSA, Bits};
//!
//! let data = b"Hello, World!";
//!
//! let rsa = RSA::new(Bits::Bits2048).unwrap();
//!
//! // Sign data
//! let signature = rsa.sign(data).unwrap();
//!
//! // Verify data
//! let is_valid = rsa.verify(&rsa.get_public_keys().unwrap(), data, signature).unwrap();
//!
//! assert!(is_valid);
//! ```

use openssl::{
    self,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
};
use serde::{
    de::{self, Visitor},
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};

mod bits;
mod encrypted;
mod key;
mod signature;

use crate::CryptError;

pub use bits::Bits;
pub use encrypted::RsaCiphertext;
pub use key::{KeyFormat, PublicKey};
pub use signature::Signature;

/// RSA is a struct that provides RSA encryption and signing functionalities.
/// It supports encrypting and decrypting data, and signing and verifying data.
///
/// # Examples
///
/// Encrypt and decrypt data:
/// ```rust
/// use cryptlib::rsa::{RSA, Bits};
///
/// let data = b"Hello, World!";
///
/// // Create a new RSA instance
/// let rsa = RSA::new(Bits::Bits2048).unwrap();
/// let public_key = rsa.get_public_keys().unwrap();
///
/// // Encrypt data
/// let ciphertext = rsa.encrypt(&public_key, data).unwrap();
///
/// // Decrypt data
/// let decrypted_data = rsa.decrypt(ciphertext).unwrap();
///
/// assert_eq!(data.to_vec(), decrypted_data);
/// ```
///
/// Sign and verify data:
/// ```rust
/// use cryptlib::rsa::{RSA, Bits};
///
/// let data = b"Hello, World!";
///
/// // Create a new RSA instance
/// let rsa = RSA::new(Bits::Bits2048).unwrap();
/// let public_key = rsa.get_public_keys().unwrap();
///
/// // Sign data
/// let signature = rsa.sign(data).unwrap();
///
/// // Verify data
/// let is_valid = rsa.verify(&public_key, data, signature).unwrap();
///
/// assert!(is_valid);
/// ```
#[derive(Debug)]
pub struct RSA {
    keys: Rsa<Private>,
    sign_keys: PKey<Private>,
}
impl RSA {
    /// Create a new instance of `RSA`. Use 2048 bits for default.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the RSA key generation fails.
    pub fn new(bits: Bits) -> Result<Self, CryptError> {
        // Generate private and public RSA key
        let keys = Rsa::generate(bits.to_bits()).map_err(CryptError::RsaError)?;

        // Generate signing keys
        let rsa_keys = Rsa::generate(bits.to_bits()).map_err(CryptError::RsaError)?;
        let sign_keys = PKey::from_rsa(rsa_keys).map_err(CryptError::RsaError)?;

        Ok(Self { keys, sign_keys })
    }

    /// Create new instance of `RSA` from private keys vec.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the RSA key deserilization fails.
    pub fn from_private_key_pems(
        rsa_private_pem: Vec<u8>,
        sign_private_pem: Vec<u8>,
    ) -> Result<Self, CryptError> {
        let keys = Rsa::private_key_from_pem(&rsa_private_pem).map_err(CryptError::RsaError)?;
        let sign_keys =
            PKey::private_key_from_pem(&sign_private_pem).map_err(CryptError::SignError)?;

        Ok(Self { keys, sign_keys })
    }

    /// Get public keys.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the public keys cannot be serialized.
    pub fn get_public_keys(&self) -> Result<PublicKey, CryptError> {
        // Get public rsa key from keys
        let rsa_public_key_der = self
            .keys
            .public_key_to_der()
            .map_err(CryptError::RsaError)?;

        // Get public sign key from sign_keys
        let sign_public_key_der = self
            .sign_keys
            .public_key_to_der()
            .map_err(CryptError::SignError)?;

        // Create `PublicKey` instance
        PublicKey::new(
            &rsa_public_key_der,
            KeyFormat::DER,
            &sign_public_key_der,
            KeyFormat::DER,
        )
    }

    /// Encrypt data.
    /// The data is encrypted using the receiver's public key.
    /// The public key needs to be the receiver's public key corresponding to the receiver's private key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the encryption fails.
    pub fn encrypt(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
    ) -> Result<RsaCiphertext, CryptError> {
        // Ciphertext buffer
        let mut ciphertext = vec![0; self.keys.size() as usize];

        // Encrypt
        receiver_public_key
            .get_rsa_key()
            .public_encrypt(data, &mut ciphertext, Padding::PKCS1_OAEP)
            .map_err(CryptError::RsaError)?;

        // Create `RsaCiphertext` instance
        Ok(RsaCiphertext::new(ciphertext))
    }

    /// Decrypt data.
    /// The data is decrypted using the internal private key.
    /// The RsaCiphertext needs to be encrypted with the internal public key corresponding to the internal private key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the decryption fails. This could mean that the data was tampered with.
    pub fn decrypt(&self, rsa_ciphertext: RsaCiphertext) -> Result<Vec<u8>, CryptError> {
        let ciphertext = rsa_ciphertext.get_component();

        // Data buffer
        let mut data = vec![0; self.keys.size() as usize];

        // Decrypt ciphertext
        let count = &self
            .keys
            .private_decrypt(&ciphertext, &mut data, Padding::PKCS1_OAEP)
            .map_err(CryptError::RsaError)?;

        // Slice decripted data to count of bytes decrypted
        Ok(data[0..count.to_owned()].to_vec())
    }

    /// Sign data.
    /// The data is signed using the internal private key and can be verified using the internal public key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Signature, CryptError> {
        // Create `signer`
        let mut signer =
            Signer::new(MessageDigest::sha512(), &self.sign_keys).map_err(CryptError::SignError)?;

        // Add data to be signed
        signer.update(data).map_err(CryptError::SignError)?;

        // Sign
        let signature = signer.sign_to_vec().map_err(CryptError::SignError)?;

        Ok(Signature::new(signature))
    }

    /// Verify data.
    /// The data is verified using the public key and signature. The public key needs to be the signer's public key corresponding to the signer's private key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the verification fails. This could mean that the data was tampered with.
    pub fn verify(
        &self,
        public_key: &PublicKey,
        data: &[u8],
        signature: Signature,
    ) -> Result<bool, CryptError> {
        // Create `verifier`
        let mut verifier = Verifier::new(MessageDigest::sha512(), public_key.get_sign_key())
            .map_err(CryptError::SignError)?;

        // Add data to be verified
        verifier.update(data).map_err(CryptError::SignError)?;

        // Verify data with signature
        verifier
            .verify(&signature.get_signature())
            .map_err(CryptError::SignError)
    }
}

impl Serialize for RSA {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let private_rsa_key = &self.keys.private_key_to_pem().map_err(|e| {
            S::Error::custom(format!("Could not serialize RSA private key! Error: {}", e))
        })?;
        let private_sign_key = &self.sign_keys.private_key_to_pem_pkcs8().map_err(|e| {
            S::Error::custom(format!(
                "Could not serialize RSA private sign key! Error: {}",
                e
            ))
        })?;

        let mut state = serializer.serialize_struct("RSA", 2)?;

        state.serialize_field("private_key", private_rsa_key)?;
        state.serialize_field("private_sign_key", private_sign_key)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for RSA {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RSAVisitor;

        impl<'de> Visitor<'de> for RSAVisitor {
            type Value = RSA;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a private_key and a private_sign_key each containing an array holding a sequence of bytes")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut private_key: Option<Vec<u8>> = None;
                let mut private_sign_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "private_key" => {
                            if private_key.is_some() {
                                return Err(de::Error::duplicate_field("private_key"));
                            }

                            private_key = Some(map.next_value()?);
                        }
                        "private_sign_key" => {
                            if private_sign_key.is_some() {
                                return Err(de::Error::duplicate_field("private_sign_key"));
                            }

                            private_sign_key = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["private_key", "private_sign_key"],
                            ))
                        }
                    }
                }

                let private_key =
                    private_key.ok_or_else(|| de::Error::missing_field("private_key"))?;
                let private_sign_key =
                    private_sign_key.ok_or_else(|| de::Error::missing_field("private_sign_key"))?;

                RSA::from_private_key_pems(private_key, private_sign_key).map_err(|e| {
                    de::Error::custom(format!("Could not initialize RSA! Error: {}", e))
                })
            }
        }

        deserializer.deserialize_struct("RSA", &["private_key", "private_sign_key"], RSAVisitor)
    }
}

#[cfg(test)]
mod rsa_tests {
    use rsa::RsaCiphertext;

    use crate::*;

    #[test]
    fn rsa() {
        let data = b"Unit test goes brrrrrrr";

        let rsa = RSA::new(Bits::Bits2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Encrypt
        let ciphertext = rsa.encrypt(&pub_key, data).unwrap();

        // Decrypt
        let out = rsa.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out);
    }

    #[test]
    fn signing() {
        let data = b"My precious data!";

        let rsa = RSA::new(Bits::Bits2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Sign
        let signature = rsa.sign(data).unwrap();

        // Verify
        let is_valid = rsa.verify(&pub_key, data, signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn rsa_serde() {
        let rsa = RSA::new(Bits::Bits2048).unwrap();

        let json = serde_json::to_string(&rsa).unwrap();

        let _: RSA = serde_json::from_str(&json).unwrap();

        assert_eq!(true, true);
    }

    #[test]
    fn rsa_invalid_decrypt() {
        let data = b"Some data to encrypt";

        let rsa = RSA::new(Bits::Bits2048).unwrap();

        // Create a new RSA instance with different keys
        let rsa_new = RSA::new(Bits::Bits2048).unwrap();
        let pub_key = rsa_new.get_public_keys().unwrap();

        // Encrypt
        let ciphertext = rsa.encrypt(&pub_key, data).unwrap();
        let mut cipher_bytes = ciphertext.get_component();
        cipher_bytes.push(5);

        // Attempt to decrypt with different keys
        let result = rsa_new.decrypt(RsaCiphertext::new(cipher_bytes));

        assert!(result.is_err());
    }

    #[test]
    fn rsa_invalid_verify() {
        let data = b"Some data to sign";

        let rsa = RSA::new(Bits::Bits2048).unwrap();

        // Sign
        let signature = rsa.sign(data).unwrap();

        // Create a new RSA instance with different keys
        let rsa_new = RSA::new(Bits::Bits2048).unwrap();
        let pub_key_new = rsa_new.get_public_keys().unwrap();

        // Attempt to verify with different public key
        let is_valid = rsa.verify(&pub_key_new, data, signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn rsa_encrypt_decrypt_large_data() {
        let data = vec![0u8; 190]; // Large data close to the limit for 2048-bit RSA with PKCS1_OAEP padding

        let rsa = RSA::new(Bits::Bits2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Encrypt
        let ciphertext = rsa.encrypt(&pub_key, &data).unwrap();

        // Decrypt
        let out = rsa.decrypt(ciphertext).unwrap();

        assert_eq!(data, out);
    }

    #[test]
    fn rsa_sign_verify_large_data() {
        let data = vec![0u8; 1024]; // Large data for signing

        let rsa = RSA::new(Bits::Bits2048).unwrap();
        let pub_key = rsa.get_public_keys().unwrap();

        // Sign
        let signature = rsa.sign(&data).unwrap();

        // Verify
        let is_valid = rsa.verify(&pub_key, &data, signature).unwrap();

        assert!(is_valid);
    }
}
