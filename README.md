# CryptLib
CryptLib is a simple to use cryptography crate for Rust that uses OpenSSL.

## Capabilities
- RSA encryption
- AES encryption
- AES encryption for streams
- SHA 224, 256, 384, 512
- SHA3 224, 256, 384, 512 
- SHA 224, 256, 384, 512 for streams
- SHA3 224, 256, 384, 512 for streams
- Composite encryption that uses AES for data and RSA for the AES key

### Getting Started
Include this section into your Cargo.toml.
```Cargo.toml
[dependencies.cryptlib]
git = "https://github.com/Marvin-Dziedzina/cryptlib"
```
