//! The `AES` struct provides methods for AES encryption and decryption using the AES-256-GCM cipher.
//! It supports both in-memory data encryption/decryption and stream-based encryption/decryption.
//! The AES-256-GCM cipher is used because it is one of the most secure and widely used symmetric encryption algorithms.
//!
//! # Examples
//!
//! Basic usage:
//!
//! ``` rust
//! use cryptlib::aes::AES;
//!
//! let data = b"Sensitive data";
//! let aad = b"Additional authenticated data";
//!
//! let aes = AES::new().unwrap();
//!
//! // Encrypt
//! let ciphertext = aes.encrypt(data, aad).unwrap();
//!
//! // Decrypt
//! let decrypted = aes.decrypt(ciphertext).unwrap();
//!
//! assert_eq!(data.to_vec(), decrypted.data);
//! assert_eq!(aad.to_vec(), decrypted.aad);
//! ```
//!
//! Stream-based encryption/decryption:
//!
//! ```
//! use cryptlib::aes::AES;
//! use std::io::{BufReader, BufWriter};
//!
//! let data = b"Stream data";
//! let aad = b"Stream AAD";
//!
//! let aes = AES::new().unwrap();
//!
//! let mut encrypted = Vec::new();
//! let mut reader = BufReader::new(&data[..]);
//! let mut writer = BufWriter::new(&mut encrypted);
//!
//! let (count, ciphertext) = aes.encrypt_stream(&mut reader, &mut writer, aad).unwrap();
//!
//! drop(writer); // Only needed to please th borrowchecker in this example.
//!
//! let mut decrypted = Vec::new();
//! let mut reader = BufReader::new(&encrypted[..count]);
//! let mut writer = BufWriter::new(&mut decrypted);
//!
//! let (count, aes_decrypted) = aes.decrypt_stream(&mut reader, &mut writer, ciphertext).unwrap();
//!
//! drop(writer); // Only needed to please th borrowchecker in this example.
//!
//! assert_eq!(data.to_vec(), decrypted[..count]);
//! assert_eq!(aes_decrypted.aad, aad);
//! ```

use std::{
    fmt::Debug,
    io::{Read, Write},
};

use openssl::{
    self,
    symm::{decrypt_aead, encrypt_aead, Cipher, Crypter, Mode},
};
use serde::{
    de::{self, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};

use crate::CryptError;

mod aes_decrypt;
mod encrypted;
mod iv;
mod key;

pub use aes_decrypt::AesDecrypted;
pub use encrypted::AesCiphertext;
pub use iv::Iv;
pub use key::AesKey;

/// AES struct provides methods for AES encryption and decryption using the AES-256-GCM cipher.
/// It supports both in-memory data encryption/decryption and stream-based encryption/decryption.
pub struct AES {
    key: AesKey,
    cipher: Cipher,
}
impl AES {
    /// Create new `AES` instance.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the AES key could not be generated.
    pub fn new() -> Result<Self, CryptError> {
        // Generate `AES` key
        let key = AesKey::new()?;

        Ok(Self {
            key,
            cipher: Self::get_cipher(),
        })
    }

    /// Create `AES` instance from `AesKey`.
    pub fn from_key(key: AesKey) -> Self {
        Self {
            key,
            cipher: Self::get_cipher(),
        }
    }

    /// Get AES key.
    pub fn get_key(&self) -> &AesKey {
        &self.key
    }

    /// Set AES key.
    pub fn set_key(&mut self, key: AesKey) {
        self.key = key;
    }

    /// Encrypt data with the internal AES key.
    /// `aad` is additional data that is not encrypted but is protected against tampering.
    /// `aad` has no size limit.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the encryption fails or if the `IV` could not be generated.
    pub fn encrypt(&self, data: &[u8], aad: &[u8]) -> Result<AesCiphertext, CryptError> {
        self.encrypt_with_key(data, aad, self.get_key())
    }

    /// Encrypt data with a given key.
    /// `aad` is additional data that is not encrypted but is protected against tampering.
    /// `aad` has no size limit.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the encryption fails or if `IV` could not be generated.
    pub fn encrypt_with_key(
        &self,
        data: &[u8],
        aad: &[u8],
        key: &AesKey,
    ) -> Result<AesCiphertext, CryptError> {
        let iv = Iv::new()?;
        let mut tag = [0; 16];

        // Encrypt
        let ciphertext = encrypt_aead(
            self.cipher,
            &key.get_bytes(),
            Some(iv.get_bytes()),
            aad,
            data,
            &mut tag,
        )
        .map_err(CryptError::AesError)?;

        Ok(AesCiphertext::new(false, ciphertext, iv, aad.to_vec(), tag))
    }

    /// Encrypt data from a reader and write to a writer.
    /// Returns the number of bytes encrypted.
    /// The key used is the internal AES key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the encryption fails or if the `IV` could not be generated.
    pub fn encrypt_stream<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        aad: &[u8],
    ) -> Result<(usize, AesCiphertext), CryptError> {
        self.encrypt_stream_with_key(reader, writer, self.get_key(), aad)
    }

    /// Encrypt data from a reader and write to a writer.
    /// Returns the number of bytes encrypted.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the encryption fails or if the `IV` could not be generated.
    pub fn encrypt_stream_with_key<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        key: &AesKey,
        aad: &[u8],
    ) -> Result<(usize, AesCiphertext), CryptError> {
        let mut tag = [0; 16];
        let iv = Iv::new()?;

        // Create new crypter for encryption
        let mut crypter = Crypter::new(
            self.cipher,
            Mode::Encrypt,
            &key.get_bytes(),
            Some(iv.get_bytes()),
        )
        .map_err(CryptError::AesError)?;
        crypter.pad(true);
        crypter.aad_update(aad).map_err(CryptError::AesError)?;

        let mut bytes_encrypted = 0;
        let mut buf = [0; 1024];
        let mut encrypted_buf: Vec<u8> = vec![0u8; 1024 + self.cipher.block_size()];

        loop {
            let n = reader.read(&mut buf).map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            };

            // Encrypt bytes
            let count = crypter
                .update(&buf[..n], &mut encrypted_buf)
                .map_err(CryptError::AesError)?;
            // Write encrypted bytes to writer
            writer
                .write_all(&encrypted_buf[..count])
                .map_err(CryptError::IoError)?;

            bytes_encrypted += count;
        }

        // Finalize encryption
        let count = crypter
            .finalize(&mut encrypted_buf)
            .map_err(CryptError::AesError)?;
        crypter.get_tag(&mut tag).map_err(CryptError::AesError)?;

        // Write remaining encrypted bytes to writer
        writer
            .write_all(&encrypted_buf[..count])
            .map_err(CryptError::IoError)?;
        writer.flush().map_err(CryptError::IoError)?;

        bytes_encrypted += count;

        Ok((
            bytes_encrypted,
            AesCiphertext::new(true, Vec::new(), iv, aad.to_vec(), tag),
        ))
    }

    /// Decript data with the internal AES key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the decryption fails or if the `ciphertext` is not a stream.
    pub fn decrypt(&self, ciphertext: AesCiphertext) -> Result<AesDecrypted, CryptError> {
        self.decrypt_with_key(ciphertext, self.get_key())
    }

    /// Decrypt data with a given key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the decryption fails or if the `ciphertext` is not a stream.
    pub fn decrypt_with_key(
        &self,
        ciphertext: AesCiphertext,
        key: &AesKey,
    ) -> Result<AesDecrypted, CryptError> {
        let (is_stream, ciphertext, iv, aad, tag) = ciphertext.get_components();
        if is_stream {
            return Err(CryptError::AesCipherError(String::from(
                "Not a normal ciphertext!",
            )));
        };

        // Decrypt
        let data = decrypt_aead(
            self.cipher,
            &key.get_bytes(),
            Some(&iv),
            &aad,
            &ciphertext,
            &tag,
        )
        .map_err(CryptError::AesError)?;

        Ok(AesDecrypted::new(false, data, aad))
    }

    /// Decrypt data from a reader and write to a writer.
    /// Returns the number of bytes decrypted and the aad.
    /// The key used is the internal AES key.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the decryption fails or if the `ciphertext` is not a stream. This could mean that the data was tampered with.
    pub fn decrypt_stream<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        ciphertext: AesCiphertext,
    ) -> Result<(usize, AesDecrypted), CryptError> {
        self.decrypt_stream_with_key(reader, writer, self.get_key(), ciphertext)
    }

    /// Decrypt data from a reader and write to a writer.
    /// Returns the number of bytes decrypted and the aad.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the decryption fails or if the `ciphertext` is not a stream. This could mean that the data was tampered with.
    pub fn decrypt_stream_with_key<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        key: &AesKey,
        ciphertext: AesCiphertext,
    ) -> Result<(usize, AesDecrypted), CryptError> {
        let (is_stream, _, iv, aad, tag) = ciphertext.get_components();
        if !is_stream {
            return Err(CryptError::AesCipherError(String::from(
                "Not a stream ciphertext!",
            )));
        };

        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &key.get_bytes(), Some(&iv))
            .map_err(CryptError::AesError)?;
        crypter.pad(true);
        crypter.aad_update(&aad).map_err(CryptError::AesError)?;
        crypter.set_tag(&tag).map_err(CryptError::AesError)?;

        let mut bytes_decrypted = 0;
        let mut encrypted_buf = [0; 1024];
        let mut buf = vec![0u8; 1024 + self.cipher.block_size()];

        loop {
            let n = reader
                .read(&mut encrypted_buf)
                .map_err(CryptError::IoError)?;

            if n == 0 {
                break;
            };

            // Decrypt bytes
            let count = crypter
                .update(&encrypted_buf[..n], &mut buf)
                .map_err(CryptError::AesError)?;
            // Write decrypted bytes to writer
            writer
                .write_all(&buf[..count])
                .map_err(CryptError::IoError)?;

            bytes_decrypted += count;
        }

        // Finalize decryption
        let count = crypter.finalize(&mut buf).map_err(CryptError::AesError)?;
        // Write remaining decrypted bytes to writer
        writer
            .write_all(&buf[..count])
            .map_err(CryptError::IoError)?;
        writer.flush().map_err(CryptError::IoError)?;

        bytes_decrypted += count;

        Ok((bytes_decrypted, AesDecrypted::new(true, Vec::new(), aad)))
    }

    /// Return aes_256_gcm cipher.
    fn get_cipher() -> Cipher {
        Cipher::aes_256_gcm()
    }
}

impl Debug for AES {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AES").field("key", &self.key).finish()
    }
}

impl Serialize for AES {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AES", 1)?;

        state.serialize_field("key", &self.key.get_bytes())?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for AES {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AESVisitor;

        impl<'de> Visitor<'de> for AESVisitor {
            type Value = AES;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an aes key in byte form with a lenght of 32 bytes")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut raw_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "key" => {
                            if raw_key.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            };

                            raw_key = Some(map.next_value()?)
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["key"])),
                    }
                }

                let raw_key = raw_key.ok_or_else(|| {
                    de::Error::custom("Could not unwrap aes key from Option!".to_string())
                })?;

                if raw_key.len() != 32 {
                    return Err(de::Error::custom(format!(
                        "Expected key length is 32 bytes, the key given has {} bytes!",
                        raw_key.len()
                    )));
                }

                let raw_key_array: [u8; 32] = raw_key.try_into().map_err(|_| {
                    de::Error::custom(
                        "Expected key length is 32 bytes, but got a different length!",
                    )
                })?;
                Ok(AES::from_key(AesKey::from_bytes(raw_key_array)))
            }
        }

        deserializer.deserialize_struct("AES", &["key"], AESVisitor)
    }
}

#[cfg(test)]
mod aes_tests {
    use std::io::{BufReader, BufWriter};

    use crate::*;

    #[test]
    fn aes() {
        let data = b"AES is a symmetric encryption.";
        let aad = b"This will be visible but can not be changed or the decription will fail";

        let aes = AES::new().unwrap();

        // Encrypt
        let ciphertext = aes.encrypt(data, aad).unwrap();

        // Decrypt
        let out = aes.decrypt(ciphertext).unwrap();

        assert_eq!(data.to_vec(), out.data);

        assert_eq!(aad.to_vec(), out.aad);
    }

    #[test]
    fn aes_stream() {
        let data = b"Test the AES symmetric en- and decryption.";
        let aad = b"Test AAD for testing stream AES.";

        let aes = AES::new().unwrap();

        let mut encrypted = Vec::new();
        let mut reader = BufReader::new(&data[..]);
        let mut writer = BufWriter::new(&mut encrypted);

        let (count, ciphertext) = aes.encrypt_stream(&mut reader, &mut writer, aad).unwrap();

        drop(writer);

        let mut decrypted: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(&encrypted[..count]);
        let mut writer = BufWriter::new(&mut decrypted);

        let (count, aes_decrypted) = aes
            .decrypt_stream(&mut reader, &mut writer, ciphertext)
            .unwrap();

        drop(writer);

        assert_eq!(data.to_vec(), decrypted[..count]);
        assert_eq!(aes_decrypted.aad, aad);
    }

    #[test]
    fn aes_serde() {
        let aes = AES::new().unwrap();

        let json = serde_json::to_string(&aes).unwrap();

        let _: AES = serde_json::from_str(&json).unwrap();
    }
}
