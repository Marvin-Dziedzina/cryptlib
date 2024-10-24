/// CryptLib is a library that provides RSA and AES encryption and decryption functions, as well as SHA hash functions.
/// It supports creating instances with RSA key sizes and AES keys, encrypting and decrypting data using a composite method (AES for data and RSA for AES key), signing and verifying data, and generating SHA hashes.
pub mod aes;
pub mod rsa;
pub mod sha;

mod bits;
mod error;
mod responses;

use std::io::{Read, Write};

pub use bits::Bits;
pub use error::CryptError;
pub use responses::CiphertextData;

use aes::{AesDecrypted, AesKey, AES};
use rsa::{PublicKey, Signature, RSA};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptLib {
    pub rsa: RSA,
    pub aes: AES,
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
        })
    }

    /// Create instance from aes key
    pub fn from_aes_key(bits: u32, aes_key: AesKey) -> Result<Self, CryptError> {
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
    pub fn encrypt_composite(
        &self,
        receiver_public_key: &PublicKey,
        data: &[u8],
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        self.encrypt_composite_with_aes_key(receiver_public_key, &self.aes.get_key(), data, aad)
    }

    /// Encrypt `data` with AES key. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
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

    pub fn encrypt_composite_stream<R: Read, W: Write>(
        &self,
        receiver_public_key: &PublicKey,
        reader: R,
        writer: W,
        aad: &[u8],
    ) -> Result<CiphertextData, CryptError> {
        self.encrypt_composite_stream_with_aes_key(
            receiver_public_key,
            &self.aes.get_key(),
            reader,
            writer,
            aad,
        )
    }

    /// Encrypt a stream. `aad` are additional bytes that are **NOT** encrypted but cant be altered.
    /// Composite meaning that the actual data is encrypted with AES and the AES key is encrypted with RSA.
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
