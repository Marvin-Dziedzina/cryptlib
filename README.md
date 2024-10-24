# CryptLib
CryptLib is a small and simple to use cryptography crate for Rust that uses OpenSSL.

## Capabilities
- RSA encryption
- AES encryption
- AES encryption for streams
- SHA 1, 224, 256, 384, 512
- SHA 1, 224, 256, 384, 512 for streams
- Composite encryption that uses AES for data and RSA for the AES key

### Getting Started
Include this section into your Cargo.toml.
```Cargo.toml
[dependencies.cryptlib]
git = "https://github.com/Marvin-Dziedzina/cryptlib"
```

### Road Map
- RSA ✅
- AES ✅
- AES Stream ✅
- SHA 1, 224, 256, 384, 512 ✅
- SHA 1, 224, 256, 384, 512 for streams ✅
- Argon2 ❌
