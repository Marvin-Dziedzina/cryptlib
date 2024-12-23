//! # RSA Key
//!
//! The `rsa` module provides the `PublicKey` struct to store the rsa public key and the sign public key.

use std::fmt::Display;

use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};
use serde::{
    de::{self, Visitor},
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};

use crate::CryptError;

/// Stores the rsa public key and the sign public key.
/// The rsa key is used for encryption and decryption.
/// The sign key is used for signing and verifying.
#[derive(Debug, Clone)]
pub struct PublicKey {
    rsa_key: Rsa<Public>,
    sign_key: PKey<Public>,
}
impl PublicKey {
    /// Create new instance of `PublicKey` from public keys.
    ///
    /// # Errors
    ///
    /// Returns a `CryptError` if the public keys can not be decoded.
    pub fn new(
        rsa_public_key: &[u8],
        rsa_public_key_format: KeyFormat,
        sign_public_key: &[u8],
        sign_public_key_format: KeyFormat,
    ) -> Result<Self, CryptError> {
        let rsa_key = match rsa_public_key_format {
            KeyFormat::DER => Rsa::public_key_from_der(rsa_public_key),
            KeyFormat::PEM => Rsa::public_key_from_pem(rsa_public_key),
        }
        .map_err(CryptError::PublicKey)?;

        let sign_key = match sign_public_key_format {
            KeyFormat::DER => PKey::public_key_from_der(sign_public_key),
            KeyFormat::PEM => PKey::public_key_from_pem(sign_public_key),
        }
        .map_err(CryptError::PublicKey)?;

        Ok(Self { rsa_key, sign_key })
    }

    /// Get the raw rsa key.
    pub fn get_rsa_key(&self) -> &Rsa<Public> {
        &self.rsa_key
    }

    /// Get the rsa key in DER format.
    pub fn get_rsa_key_der(&self) -> Result<Vec<u8>, CryptError> {
        self.rsa_key
            .public_key_to_der()
            .map_err(CryptError::PublicKey)
    }

    /// Get the rsa key in PEM format.
    pub fn get_rsa_key_pem(&self) -> Result<Vec<u8>, CryptError> {
        self.rsa_key
            .public_key_to_pem()
            .map_err(CryptError::PublicKey)
    }

    /// Get the raw sign key.
    pub fn get_sign_key(&self) -> &PKey<Public> {
        &self.sign_key
    }

    /// Get the sign key in DER format.
    pub fn get_sign_key_der(&self) -> Result<Vec<u8>, CryptError> {
        self.sign_key
            .public_key_to_der()
            .map_err(CryptError::PublicKey)
    }

    /// Get the sign key in PEM format.
    pub fn get_sign_key_pem(&self) -> Result<Vec<u8>, CryptError> {
        self.sign_key
            .public_key_to_pem()
            .map_err(CryptError::PublicKey)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PublicKey", 2)?;

        let rsa_public_key = &self.rsa_key.public_key_to_pem().map_err(|e| {
            S::Error::custom(format!(
                "Could not serialize `rsa_key` from `PublicKey`! Error: {}",
                e
            ))
        })?;
        let sign_public_key = &self.sign_key.public_key_to_pem().map_err(|e| {
            S::Error::custom(format!(
                "Could not serialize `sign_key` from `PublicKey`! Error: {}",
                e
            ))
        })?;

        state.serialize_field("rsa_public_key", &rsa_public_key)?;
        state.serialize_field("sign_public_key", &sign_public_key)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a rsa_public_key and a sign_public_key")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut rsa_public_key: Option<Vec<u8>> = None;
                let mut sign_public_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "rsa_public_key" => {
                            if rsa_public_key.is_some() {
                                return Err(de::Error::duplicate_field("rsa_public_key"));
                            };

                            rsa_public_key = Some(map.next_value()?);
                        }
                        "sign_public_key" => {
                            if sign_public_key.is_some() {
                                return Err(de::Error::duplicate_field("sign_public_key"));
                            };

                            sign_public_key = Some(map.next_value()?)
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["rsa_public_key", "sign_public_key"],
                            ))
                        }
                    }
                }

                let rsa_public_key =
                    rsa_public_key.ok_or_else(|| de::Error::missing_field("rsa_public_key"))?;
                let sign_public_key =
                    sign_public_key.ok_or_else(|| de::Error::missing_field("sign_public_key"))?;

                PublicKey::new(
                    &rsa_public_key,
                    KeyFormat::PEM,
                    &sign_public_key,
                    KeyFormat::PEM,
                )
                .map_err(|e| de::Error::custom(format!("{}", e)))
            }
        }

        deserializer.deserialize_struct(
            "PublicKey",
            &["rsa_public_key", "sign_public_key"],
            PublicKeyVisitor,
        )
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RSA KEY: {}; SIGN KEY: {}",
            String::from_utf8_lossy(&self.get_rsa_key_pem().expect("Could not get rsa key pem!")),
            String::from_utf8_lossy(
                &self
                    .get_sign_key_pem()
                    .expect("Could not get sign key pem!")
            )
        )
    }
}

/// Common supported key formats
#[derive(Debug, Serialize, Deserialize)]
pub enum KeyFormat {
    PEM,
    DER,
}

#[cfg(test)]
mod public_key_tests {
    use rsa::KeyFormat;

    use crate::*;

    #[test]
    fn public_key_serde() {
        let public_key = RSA::new(Bits::Bits2048).unwrap().get_public_keys().unwrap();

        let json = serde_json::to_string(&public_key).unwrap();

        let _: PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn get_public_key() {
        get_pub_key().unwrap();
    }

    #[test]
    fn get_rsa_key_der() {
        let public_key = get_pub_key().unwrap();
        public_key.get_rsa_key_der().unwrap();
    }

    #[test]
    fn get_rsa_key_pem() {
        let public_key = get_pub_key().unwrap();
        public_key.get_rsa_key_pem().unwrap();
    }

    #[test]
    fn get_sign_key_der() {
        let public_key = get_pub_key().unwrap();
        public_key.get_sign_key_der().unwrap();
    }

    #[test]
    fn get_sign_key_pem() {
        let public_key = get_pub_key().unwrap();
        public_key.get_sign_key_pem().unwrap();
    }

    fn get_pub_key() -> Result<PublicKey, CryptError> {
        let rsa = RSA::new(Bits::Bits2048)?;
        rsa.get_public_keys()
    }

    #[test]
    fn public_key_display() {
        let public_key = get_pub_key().unwrap();
        let display_string = format!("{}", public_key);
        assert!(display_string.contains("RSA KEY:"));
        assert!(display_string.contains("SIGN KEY:"));
    }

    #[test]
    fn public_key_new_with_invalid_rsa_key() {
        let invalid_rsa_key = b"invalid_rsa_key";
        let sign_key = get_pub_key().unwrap().get_sign_key_pem().unwrap();
        let result = PublicKey::new(invalid_rsa_key, KeyFormat::PEM, &sign_key, KeyFormat::PEM);
        assert!(result.is_err());
    }

    #[test]
    fn public_key_new_with_invalid_sign_key() {
        let rsa_key = get_pub_key().unwrap().get_rsa_key_pem().unwrap();
        let invalid_sign_key = b"invalid_sign_key";
        let result = PublicKey::new(&rsa_key, KeyFormat::PEM, invalid_sign_key, KeyFormat::PEM);
        assert!(result.is_err());
    }

    #[test]
    fn public_key_serialize_deserialize() {
        let public_key = get_pub_key().unwrap();
        let serialized = serde_json::to_string(&public_key).unwrap();
        let deserialized: PublicKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(
            public_key.get_rsa_key_pem().unwrap(),
            deserialized.get_rsa_key_pem().unwrap()
        );
        assert_eq!(
            public_key.get_sign_key_pem().unwrap(),
            deserialized.get_sign_key_pem().unwrap()
        );
    }

    #[test]
    fn public_key_get_rsa_key() {
        let public_key = get_pub_key().unwrap();
        let rsa_key = public_key.get_rsa_key();
        assert!(rsa_key.public_key_to_pem().is_ok());
    }

    #[test]
    fn public_key_get_sign_key() {
        let public_key = get_pub_key().unwrap();
        let sign_key = public_key.get_sign_key();
        assert!(sign_key.public_key_to_pem().is_ok());
    }
}
