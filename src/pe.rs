#[derive(Debug, PartialEq)]
pub enum PeError {
    FileTooSmall,
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidOffset,
    InvalidMagic,
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
pub struct OptionalHeaderCommon {
    pub magic: Magic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,

    pub section_alignment: u32,
    pub file_alignment: u32,

    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,

    pub major_image_version: u16,
    pub minor_image_version: u16,

    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

#[derive(Debug, PartialEq)]
pub struct OptionalHeader32 {
    pub common: OptionalHeaderCommon,
    pub base_of_data: u32,
    pub image_base: u32,
}

#[derive(Debug, PartialEq)]
pub struct OptionalHeader64 {
    pub common: OptionalHeaderCommon,
    pub image_base: u64,
}

#[derive(Debug, PartialEq)]
pub enum OptionalHeader {
    PE32(OptionalHeader32),
    PE32Plus(OptionalHeader64),
}

#[derive(Debug, PartialEq)]
pub struct PeFile {
    pub e_lfanew: u32,
    pub coff_header: CoffHeader,
    pub optional_header: OptionalHeader,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Magic {
    PE32,
    PE32Plus,
}

pub fn parse(data: &[u8]) -> Result<PeFile, PeError> {
    if data.len() < 0x40 {
        return Err(PeError::FileTooSmall);
    }
    if data[0..2] != [0x4D, 0x5A] {
        return Err(PeError::InvalidDosSignature);
    }
    let e_lfanew_bytes = &data[0x3C..0x40];
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes.try_into().unwrap());
    let pe_offset = e_lfanew as usize;

    let pe_signature = checked_range(data, pe_offset, 4)?;
    if pe_signature != [0x50, 0x45, 0x00, 0x00] {
        return Err(PeError::InvalidPeSignature);
    }

    let mut current_offset = pe_offset + 4;

    let machine = read_u16(data, &mut current_offset)?;
    let number_of_sections = read_u16(data, &mut current_offset)?;
    let time_date_stamp = read_u32(data, &mut current_offset)?;
    let pointer_to_symbol_table = read_u32(data, &mut current_offset)?;
    let number_of_symbols = read_u32(data, &mut current_offset)?;
    let size_of_optional_header = read_u16(data, &mut current_offset)?;
    let characteristics = read_u16(data, &mut current_offset)?;

    let mut optional_offset = 0;

    let optional_header_data =
        checked_range(data, current_offset, size_of_optional_header as usize)?;

    let magic_value = read_u16(optional_header_data, &mut optional_offset)?;
    let major_linker_version = read_u8(optional_header_data, &mut optional_offset)?;
    let minor_linker_version = read_u8(optional_header_data, &mut optional_offset)?;
    let size_of_code = read_u32(optional_header_data, &mut optional_offset)?;
    let size_of_initialized_data = read_u32(optional_header_data, &mut optional_offset)?;
    let size_of_uninitialized_data = read_u32(optional_header_data, &mut optional_offset)?;
    let address_of_entry_point = read_u32(optional_header_data, &mut optional_offset)?;
    let base_of_code = read_u32(optional_header_data, &mut optional_offset)?;

    let magic = match magic_value {
        0x10B => Magic::PE32,
        0x20B => Magic::PE32Plus,
        _ => return Err(PeError::InvalidMagic),
    };

    let (base_of_data, image_base_32, image_base_64) = match magic {
        Magic::PE32 => {
            let base_of_data = read_u32(optional_header_data, &mut optional_offset)?;
            let image_base = read_u32(optional_header_data, &mut optional_offset)?;
            (Some(base_of_data), Some(image_base), None)
        }
        Magic::PE32Plus => {
            let image_base = read_u64(optional_header_data, &mut optional_offset)?;
            (None, None, Some(image_base))
        }
    };

    let section_alignment = read_u32(optional_header_data, &mut optional_offset)?;
    let file_alignment = read_u32(optional_header_data, &mut optional_offset)?;
    let major_operating_system_version = read_u16(optional_header_data, &mut optional_offset)?;
    let minor_operating_system_version = read_u16(optional_header_data, &mut optional_offset)?;
    let major_image_version = read_u16(optional_header_data, &mut optional_offset)?;
    let minor_image_version = read_u16(optional_header_data, &mut optional_offset)?;
    let major_subsystem_version = read_u16(optional_header_data, &mut optional_offset)?;
    let minor_subsystem_version = read_u16(optional_header_data, &mut optional_offset)?;
    let win32_version_value = read_u32(optional_header_data, &mut optional_offset)?;
    let size_of_image = read_u32(optional_header_data, &mut optional_offset)?;
    let size_of_headers = read_u32(optional_header_data, &mut optional_offset)?;
    let checksum = read_u32(optional_header_data, &mut optional_offset)?;
    let subsystem = read_u16(optional_header_data, &mut optional_offset)?;
    let dll_characteristics = read_u16(optional_header_data, &mut optional_offset)?;

    let optional_header = match magic {
        Magic::PE32 => OptionalHeader::PE32(OptionalHeader32 {
            common: OptionalHeaderCommon {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                checksum,
                subsystem,
                dll_characteristics,
            },
            base_of_data: base_of_data.unwrap(),
            image_base: image_base_32.unwrap(),
        }),

        Magic::PE32Plus => OptionalHeader::PE32Plus(OptionalHeader64 {
            common: OptionalHeaderCommon {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                checksum,
                subsystem,
                dll_characteristics,
            },
            image_base: image_base_64.unwrap(),
        }),
    };

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
        optional_header,
    })
}

fn checked_range(data: &[u8], start: usize, size: usize) -> Result<&[u8], PeError> {
    let end = start.checked_add(size).ok_or(PeError::InvalidOffset)?;

    if end > data.len() {
        return Err(PeError::InvalidOffset);
    }

    Ok(&data[start..end])
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, PeError> {
    let bytes = checked_range(data, *offset, 8)?;
    *offset += 8;

    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, PeError> {
    let bytes = checked_range(data, *offset, 4)?;
    *offset += 4;

    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16, PeError> {
    let bytes = checked_range(data, *offset, 2)?;
    *offset += 2;

    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, PeError> {
    let bytes = checked_range(data, *offset, 1)?;
    *offset += 1;

    Ok(u8::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const MAGIC_SIZE: usize = 2;
    const MAJOR_LINKER_VERSION_SIZE: usize = 1;
    const MINOR_LINKER_VERSION_SIZE: usize = 1;
    const SIZE_OF_CODE_SIZE: usize = 4;
    const SIZE_OF_INITIALIZED_DATA_SIZE: usize = 4;
    const SIZE_OF_UNITIALIZED_DATA_SIZE: usize = 4;
    const ADDRESS_OF_ENTRY_POINT_SIZE: usize = 4;
    const BASE_OF_CODE_SIZE: usize = 4;

    const BASE_OF_DATA_SIZE: usize = 4;
    const IMAGE_BASE_32_SIZE: usize = 4;
    const IMAGE_BASE_64_SIZE: usize = 8;

    const COFF_HEADER_SIZE: usize = MACHINE_SIZE
        + NUMBER_OF_SECTIONS_SIZE
        + TIME_DATE_STAMP_SIZE
        + POINTER_TO_SYMBOL_TABLE_SIZE
        + NUMBER_OF_SYMBOLS_SIZE
        + SIZE_OF_OPTIONAL_HEADER_SIZE
        + CHARACTERISTICS_SIZE;

    fn serialize_common(curr: &mut usize, buffer: &mut [u8], common: &OptionalHeaderCommon) {
        buffer[*curr..*curr + MAJOR_LINKER_VERSION_SIZE]
            .copy_from_slice(&common.major_linker_version.to_le_bytes());
        *curr += MAJOR_LINKER_VERSION_SIZE;

        buffer[*curr..*curr + MINOR_LINKER_VERSION_SIZE]
            .copy_from_slice(&common.minor_linker_version.to_le_bytes());
        *curr += MINOR_LINKER_VERSION_SIZE;

        buffer[*curr..*curr + SIZE_OF_CODE_SIZE]
            .copy_from_slice(&common.size_of_code.to_le_bytes());
        *curr += SIZE_OF_CODE_SIZE;

        buffer[*curr..*curr + SIZE_OF_INITIALIZED_DATA_SIZE]
            .copy_from_slice(&common.size_of_initialized_data.to_le_bytes());
        *curr += SIZE_OF_INITIALIZED_DATA_SIZE;

        buffer[*curr..*curr + SIZE_OF_UNITIALIZED_DATA_SIZE]
            .copy_from_slice(&common.size_of_uninitialized_data.to_le_bytes());
        *curr += SIZE_OF_UNITIALIZED_DATA_SIZE;

        buffer[*curr..*curr + ADDRESS_OF_ENTRY_POINT_SIZE]
            .copy_from_slice(&common.address_of_entry_point.to_le_bytes());
        *curr += ADDRESS_OF_ENTRY_POINT_SIZE;

        buffer[*curr..*curr + BASE_OF_CODE_SIZE]
            .copy_from_slice(&common.base_of_code.to_le_bytes());
        *curr += BASE_OF_CODE_SIZE;
    }

    fn serialize_trailing_common(
        curr: &mut usize,
        buffer: &mut [u8],
        common: &OptionalHeaderCommon,
    ) {
        buffer[*curr..*curr + 4].copy_from_slice(&common.section_alignment.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&common.file_alignment.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 2]
            .copy_from_slice(&common.major_operating_system_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2]
            .copy_from_slice(&common.minor_operating_system_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&common.major_image_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&common.minor_image_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&common.major_subsystem_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&common.minor_subsystem_version.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 4].copy_from_slice(&common.win32_version_value.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&common.size_of_image.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&common.size_of_headers.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&common.checksum.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 2].copy_from_slice(&common.subsystem.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&common.dll_characteristics.to_le_bytes());
    }

    fn create_valid_pe_buffer(
        e_lfanew: u32,
        coff_header: &CoffHeader,
        optional_header: Option<&OptionalHeader>,
    ) -> Vec<u8> {
        let pe_offset = e_lfanew as usize;
        let opt_size = coff_header.size_of_optional_header as usize;
        let total_size = pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE + opt_size;
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
        curr += CHARACTERISTICS_SIZE;

        if let Some(opt) = optional_header {
            match opt {
                OptionalHeader::PE32(pe32) => {
                    let magic_val: u16 = 0x10B;
                    buffer[curr..curr + MAGIC_SIZE].copy_from_slice(&magic_val.to_le_bytes());
                    curr += MAGIC_SIZE;

                    serialize_common(&mut curr, &mut buffer, &pe32.common);

                    buffer[curr..curr + BASE_OF_DATA_SIZE]
                        .copy_from_slice(&pe32.base_of_data.to_le_bytes());
                    curr += BASE_OF_DATA_SIZE;

                    buffer[curr..curr + IMAGE_BASE_32_SIZE]
                        .copy_from_slice(&pe32.image_base.to_le_bytes());
                    curr += IMAGE_BASE_32_SIZE;

                    serialize_trailing_common(&mut curr, &mut buffer, &pe32.common);
                }
                OptionalHeader::PE32Plus(pe64) => {
                    let magic_val: u16 = 0x20B;
                    buffer[curr..curr + MAGIC_SIZE].copy_from_slice(&magic_val.to_le_bytes());
                    curr += MAGIC_SIZE;

                    serialize_common(&mut curr, &mut buffer, &pe64.common);

                    buffer[curr..curr + IMAGE_BASE_64_SIZE]
                        .copy_from_slice(&pe64.image_base.to_le_bytes());
                    curr += IMAGE_BASE_64_SIZE;

                    serialize_trailing_common(&mut curr, &mut buffer, &pe64.common);
                }
            }
        }

        buffer
    }

    fn sample_common(magic: Magic) -> OptionalHeaderCommon {
        OptionalHeaderCommon {
            magic,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0x1000,
            size_of_initialized_data: 0x2000,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0x1234,
            base_of_code: 0x1000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0x5000,
            size_of_headers: 0x400,
            checksum: 0,
            subsystem: 3,
            dll_characteristics: 0x8140,
        }
    }

    #[test]
    fn test_valid_pe32_parsing() {
        let coff_header = CoffHeader {
            machine: 0x014C,
            number_of_sections: 3,
            time_date_stamp: 0x60000000,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00E0,
            characteristics: 0x0102,
        };

        let optional_header = OptionalHeader::PE32(OptionalHeader32 {
            common: sample_common(Magic::PE32),
            base_of_data: 0x2000,
            image_base: 0x00400000,
        });

        let buffer = create_valid_pe_buffer(0x80, &coff_header, Some(&optional_header));
        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
                optional_header,
            })
        );
    }

    #[test]
    fn test_valid_pe32plus_parsing() {
        let coff_header = CoffHeader {
            machine: 0x8664,
            number_of_sections: 6,
            time_date_stamp: 0x60000000,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00F0,
            characteristics: 0x0022,
        };

        let optional_header = OptionalHeader::PE32Plus(OptionalHeader64 {
            common: sample_common(Magic::PE32Plus),
            image_base: 0x0000000140000000,
        });

        let buffer = create_valid_pe_buffer(0x80, &coff_header, Some(&optional_header));
        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
                optional_header,
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
            size_of_optional_header: 0x00E0,
            characteristics: 0,
        };

        let mut buffer = create_valid_pe_buffer(0x80, &coff_header, None);
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
