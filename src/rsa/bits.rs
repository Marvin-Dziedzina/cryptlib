/// Enum to represent the bits of the RSA key.
#[derive(Debug)]
pub enum Bits {
    Bits1024,
    Bits2048,
    Bits3072,
    Bits4096,
    Custom(u32),
}
impl Bits {
    /// Convert the Bits enum to u32.
    pub fn to_bits(&self) -> u32 {
        match self {
            Bits::Bits1024 => 1024,
            Bits::Bits2048 => 2048,
            Bits::Bits3072 => 3072,
            Bits::Bits4096 => 4096,
            Bits::Custom(bits) => *bits,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::Bits;

    #[test]
    fn test_bits_to_bits() {
        assert_eq!(Bits::Bits1024.to_bits(), 1024);
        assert_eq!(Bits::Bits2048.to_bits(), 2048);
        assert_eq!(Bits::Bits3072.to_bits(), 3072);
        assert_eq!(Bits::Bits4096.to_bits(), 4096);
        assert_eq!(Bits::Custom(512).to_bits(), 512);
        assert_eq!(Bits::Custom(8192).to_bits(), 8192);
    }

    #[test]
    fn test_custom_bits() {
        let custom_bits = Bits::Custom(16384);
        assert_eq!(custom_bits.to_bits(), 16384);
    }
}
