pub enum Bits {
    Bits1024,
    Bits2048,
    Bits3072,
    Bits4096,
    Custom(u32),
}
impl Bits {
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
