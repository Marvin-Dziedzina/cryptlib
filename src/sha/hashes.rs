pub enum HashType {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

pub enum Hash {
    Sha1([u8; 20]),
    Sha224([u8; 28]),
    Sha256([u8; 32]),
    Sha384([u8; 48]),
    Sha512([u8; 64]),
}
