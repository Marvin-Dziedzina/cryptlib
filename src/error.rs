use std::{error::Error, fmt::Display};

use openssl::error::ErrorStack;

/// Error type for the `crypt` module.
#[derive(Debug)]
pub enum CryptError {
    RsaError(ErrorStack),
    AesError(ErrorStack),
    AesKeyError(String),
    AesCipherError(String),
    SignError(ErrorStack),
    PublicKey(ErrorStack),
    RandError(ErrorStack),
    IoError(std::io::Error),
    InvalidHashLength,
}

impl Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::RsaError(e) => write!(f, "RSA Error: {}", e),
            CryptError::AesError(e) => write!(f, "AES Error: {}", e),
            CryptError::AesKeyError(e) => write!(f, "AES Key Lenght Error: {}", e),
            CryptError::AesCipherError(e) => write!(f, "AES Cipher Error: {}", e),
            CryptError::SignError(e) => write!(f, "Sign Error: {}", e),
            CryptError::PublicKey(e) => write!(f, "Public Key Error: {}", e),
            CryptError::RandError(e) => write!(f, "Rand Error: {}", e),
            CryptError::IoError(e) => write!(f, "IO Error: {}", e),
            CryptError::InvalidHashLength => write!(f, "Invalid Hash Length"),
        }
    }
}

impl Error for CryptError {}
