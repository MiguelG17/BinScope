const PE_SIGNATURE_SIZE: usize = 4;
const MACHINE_SIZE: usize = 2;
const PE_SIGNATURE: [u8; 4] = [0x50, 0x45, 0x00, 0x00];
const DOS_SIGNATURE: [u8; 2] = [0x4D, 0x5A];
const NUMBER_OF_SECTIONS_SIZE: usize = 2;
const TIME_DATE_STAMP_SIZE: usize = 4;
const POINTER_TO_SYMBOL_TABLE_SIZE: usize = 4;
const NUMBER_OF_SYMBOLS_SIZE: usize = 4;
const SIZE_OF_OPTIONAL_HEADER_SIZE: usize = 2;
const CHARACTERISTICS_SIZE: usize = 2;

#[derive(Debug, PartialEq)]
pub enum PeError {
    FileTooSmall,
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidOffset,
}
#[derive(Debug, PartialEq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}
#[derive(Debug, PartialEq)]
pub struct PeFile {
    pub e_lfanew: u32,
    pub coff_header: CoffHeader,
}

pub fn parse(data: &[u8]) -> Result<PeFile, PeError> {
    if data.len() < 0x40 {
        return Err(PeError::FileTooSmall);
    }
    if data[0..2] != DOS_SIGNATURE {
        return Err(PeError::InvalidDosSignature);
    }
    let e_lfanew_bytes = &data[0x3C..0x40];

    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes.try_into().unwrap());

    let pe_offset = e_lfanew as usize;

    let pe_signature = checked_range(data, pe_offset, PE_SIGNATURE_SIZE)?;
    if pe_signature != PE_SIGNATURE {
        return Err(PeError::InvalidPeSignature);
    }

    let mut current_offset = pe_offset + PE_SIGNATURE_SIZE;

    let pe_machine = checked_range(data, current_offset, MACHINE_SIZE)?;

    let machine = u16::from_le_bytes(pe_machine.try_into().unwrap());
    current_offset += MACHINE_SIZE;

    let pe_number_of_sections = checked_range(data, current_offset, NUMBER_OF_SECTIONS_SIZE)?;

    let number_of_sections = u16::from_le_bytes(pe_number_of_sections.try_into().unwrap());
    current_offset += NUMBER_OF_SECTIONS_SIZE;

    let pe_time_date_stamp = checked_range(data, current_offset, TIME_DATE_STAMP_SIZE)?;

    let time_date_stamp = u32::from_le_bytes(pe_time_date_stamp.try_into().unwrap());
    current_offset += TIME_DATE_STAMP_SIZE;

    let pe_pointer_to_symbol_table =
        checked_range(data, current_offset, POINTER_TO_SYMBOL_TABLE_SIZE)?;

    let pointer_to_symbol_table =
        u32::from_le_bytes(pe_pointer_to_symbol_table.try_into().unwrap());
    current_offset += POINTER_TO_SYMBOL_TABLE_SIZE;

    let pe_number_of_symbols = checked_range(data, current_offset, NUMBER_OF_SYMBOLS_SIZE)?;

    let number_of_symbols = u32::from_le_bytes(pe_number_of_symbols.try_into().unwrap());
    current_offset += NUMBER_OF_SYMBOLS_SIZE;

    let pe_size_of_optional_header =
        checked_range(data, current_offset, SIZE_OF_OPTIONAL_HEADER_SIZE)?;

    let size_of_optional_header =
        u16::from_le_bytes(pe_size_of_optional_header.try_into().unwrap());
    current_offset += SIZE_OF_OPTIONAL_HEADER_SIZE;

    let pe_characteristics = checked_range(data, current_offset, CHARACTERISTICS_SIZE)?;

    let characteristics = u16::from_le_bytes(pe_characteristics.try_into().unwrap());

    Ok(PeFile {
        e_lfanew,
        coff_header: CoffHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        },
    })
}

fn checked_range(data: &[u8], start: usize, size: usize) -> Result<&[u8], PeError> {
    let end = start.checked_add(size).ok_or(PeError::InvalidOffset)?;

    if end > data.len() {
        return Err(PeError::InvalidOffset);
    }

    Ok(&data[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const COFF_HEADER_SIZE: usize = MACHINE_SIZE
        + NUMBER_OF_SECTIONS_SIZE
        + TIME_DATE_STAMP_SIZE
        + POINTER_TO_SYMBOL_TABLE_SIZE
        + NUMBER_OF_SYMBOLS_SIZE
        + SIZE_OF_OPTIONAL_HEADER_SIZE
        + CHARACTERISTICS_SIZE;

    fn create_valid_pe_buffer(e_lfanew: u32, coff_header: &CoffHeader) -> Vec<u8> {
        let pe_offset = e_lfanew as usize;
        let total_size = pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE;
        let mut buffer = vec![0u8; total_size];

        // Firma DOS "MZ"
        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);

        // e_lfanew
        buffer[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Firma PE "PE\0\0"
        buffer[pe_offset..pe_offset + PE_SIGNATURE_SIZE].copy_from_slice(&PE_SIGNATURE);

        // COFF Header (20 bytes)
        let mut curr = pe_offset + PE_SIGNATURE_SIZE;

        buffer[curr..curr + MACHINE_SIZE].copy_from_slice(&coff_header.machine.to_le_bytes());
        curr += MACHINE_SIZE;

        buffer[curr..curr + NUMBER_OF_SECTIONS_SIZE]
            .copy_from_slice(&coff_header.number_of_sections.to_le_bytes());
        curr += NUMBER_OF_SECTIONS_SIZE;

        buffer[curr..curr + TIME_DATE_STAMP_SIZE]
            .copy_from_slice(&coff_header.time_date_stamp.to_le_bytes());
        curr += TIME_DATE_STAMP_SIZE;

        buffer[curr..curr + POINTER_TO_SYMBOL_TABLE_SIZE]
            .copy_from_slice(&coff_header.pointer_to_symbol_table.to_le_bytes());
        curr += POINTER_TO_SYMBOL_TABLE_SIZE;

        buffer[curr..curr + NUMBER_OF_SYMBOLS_SIZE]
            .copy_from_slice(&coff_header.number_of_symbols.to_le_bytes());
        curr += NUMBER_OF_SYMBOLS_SIZE;

        buffer[curr..curr + SIZE_OF_OPTIONAL_HEADER_SIZE]
            .copy_from_slice(&coff_header.size_of_optional_header.to_le_bytes());
        curr += SIZE_OF_OPTIONAL_HEADER_SIZE;

        buffer[curr..curr + CHARACTERISTICS_SIZE]
            .copy_from_slice(&coff_header.characteristics.to_le_bytes());

        buffer
    }

    #[test]
    fn test_valid_pe_parsing() {
        let coff_header = CoffHeader {
            machine: 0x8664,
            number_of_sections: 6,
            time_date_stamp: 0x60000000,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00F0,
            characteristics: 0x0022,
        };

        let buffer = create_valid_pe_buffer(0x80, &coff_header);

        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
            })
        );
    }

    #[test]
    fn test_file_too_small() {
        let buffer = vec![0u8; 0x3F];
        assert_eq!(parse(&buffer), Err(PeError::FileTooSmall));
    }

    #[test]
    fn test_invalid_dos_signature() {
        let mut buffer = vec![0u8; 0x40];
        buffer[0..2].copy_from_slice(b"NO");
        assert_eq!(parse(&buffer), Err(PeError::InvalidDosSignature));
    }

    #[test]
    fn test_invalid_pe_signature() {
        let coff_header = CoffHeader {
            machine: 0x014C,
            number_of_sections: 3,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
        };

        let mut buffer = create_valid_pe_buffer(0x80, &coff_header);
        buffer[0x80..0x84].copy_from_slice(b"FAIL");
        assert_eq!(parse(&buffer), Err(PeError::InvalidPeSignature));
    }

    #[test]
    fn test_offset_out_of_bounds() {
        let mut buffer = vec![0u8; 0x40];
        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);
        buffer[0x3C..0x40].copy_from_slice(&200u32.to_le_bytes());

        assert_eq!(parse(&buffer), Err(PeError::InvalidOffset));
    }

    #[test]
    fn test_truncated_machine_bytes() {
        let e_lfanew: u32 = 0x40;
        let pe_offset = e_lfanew as usize;

        let truncated_len = pe_offset + PE_SIGNATURE_SIZE + 1;
        let mut buffer = vec![0u8; truncated_len];

        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);
        buffer[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        buffer[pe_offset..pe_offset + PE_SIGNATURE_SIZE].copy_from_slice(&PE_SIGNATURE);
        buffer[pe_offset + PE_SIGNATURE_SIZE] = 0x64;

        assert_eq!(parse(&buffer), Err(PeError::InvalidOffset));
    }

    #[test]
    fn test_truncated_time_date_stamp() {
        let e_lfanew: u32 = 0x40;
        let pe_offset = e_lfanew as usize;

        let truncated_len =
            pe_offset + PE_SIGNATURE_SIZE + MACHINE_SIZE + NUMBER_OF_SECTIONS_SIZE + 2;
        let mut buffer = vec![0u8; truncated_len];

        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);
        buffer[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        buffer[pe_offset..pe_offset + PE_SIGNATURE_SIZE].copy_from_slice(&PE_SIGNATURE);

        assert_eq!(parse(&buffer), Err(PeError::InvalidOffset));
    }

    #[test]
    fn test_truncated_characteristics() {
        let e_lfanew: u32 = 0x40;
        let pe_offset = e_lfanew as usize;

        let truncated_len = pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE - 1;
        let mut buffer = vec![0u8; truncated_len];

        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);
        buffer[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        buffer[pe_offset..pe_offset + PE_SIGNATURE_SIZE].copy_from_slice(&PE_SIGNATURE);

        assert_eq!(parse(&buffer), Err(PeError::InvalidOffset));
    }
}
