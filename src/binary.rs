
#[derive(Debug)]
pub enum BinaryFormat {
    Pe,
    Elf,
    Unknown,
}

pub fn detect_format(data: &[u8]) -> BinaryFormat{
    if data.is_empty() {
        return BinaryFormat::Unknown
    }
    
    match data {
        [0x4D, 0x5A, ..]  => BinaryFormat::Pe,
        [0x7F, 0x45, 0x4C, 0x46, ..] => BinaryFormat::Elf,
        _ => BinaryFormat::Unknown,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe() {
        let data = [0x4D, 0x5A];

        assert!(matches!(
            detect_format(&data),
            BinaryFormat::Pe
        ));
    }

    #[test]
    fn detects_elf() {
        let data = [0x7F, 0x45, 0x4C, 0x46];

        assert!(matches!(
            detect_format(&data),
            BinaryFormat::Elf
        ));
    }

    #[test]
    fn detects_unknown() {
        let data = [0x01, 0x02, 0x03];

        assert!(matches!(
            detect_format(&data),
            BinaryFormat::Unknown
        ));
    }

    #[test]
    fn detects_empty_data() {
        let data: [u8; 0] = [];

        assert!(matches!(
            detect_format(&data),
            BinaryFormat::Unknown
        ));
    }
}