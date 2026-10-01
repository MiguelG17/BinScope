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
    pub machine: Machine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Machine {
    X86,
    AMD64,
    Arm,
    Arm64,
    Unknown(u16),
}

fn interpret_machine(value: u16) -> Machine {
    match value {
        0x014C => Machine::X86,
        0x8664 => Machine::AMD64,
        0x01C0 => Machine::Arm,
        0xAA64 => Machine::Arm64,
        other => Machine::Unknown(other),
    }
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

    pub data_directories: DataDirectories,
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
    pub sections: Vec<SectionHeader>,
}

#[derive(Debug, PartialEq)]
pub struct ImportModule {
    pub name: String,
    pub functions: Vec<String>,
}

impl PeFile {
    pub fn section_names(&self) -> Vec<String> {
        self.sections
            .iter()
            .map(|section| section.name_as_string())
            .collect()
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.sections {
            let start = section.virtual_address;
            let end = start + section.size_of_raw_data;

            if rva >= start && rva < end {
                return Some(section.pointer_to_raw_data + (rva - section.virtual_address));
            }
        }

        None
    }

    pub fn imported_dlls(&self, data: &[u8]) -> Result<Vec<ImportModule>, PeError> {
        let directories = match &self.optional_header {
            OptionalHeader::PE32(header) => &header.common.data_directories,
            OptionalHeader::PE32Plus(header) => &header.common.data_directories,
        };

        let import_directory = match directories.get(DataDirectoryType::Import) {
            Some(dir) if dir.virtual_address != 0 => dir,
            _ => return Ok(Vec::new()),
        };

        let mut offset = self
            .rva_to_file_offset(import_directory.virtual_address)
            .ok_or(PeError::InvalidOffset)? as usize;

        let mut modules = Vec::new();

        loop {
            let descriptor = parse_import_descriptor(data, &mut offset)?;

            if descriptor.original_first_thunk == 0
                && descriptor.time_date_stamp == 0
                && descriptor.forwarder_chain == 0
                && descriptor.name_rva == 0
                && descriptor.first_thunk == 0
            {
                break;
            }

            let name_offset = self
                .rva_to_file_offset(descriptor.name_rva)
                .ok_or(PeError::InvalidOffset)? as usize;

            let dll_name = read_c_string(data, name_offset)?;

            let thunk_rva = if descriptor.original_first_thunk != 0 {
                descriptor.original_first_thunk
            } else {
                descriptor.first_thunk
            };

            let functions = parse_import_lookup_table(self, data, thunk_rva)?;

            modules.push(ImportModule {
                name: dll_name,
                functions,
            });
        }

        Ok(modules)
    }
}

#[derive(Debug, PartialEq)]
pub struct ImportByName {
    pub hint: u16,
    pub name: String,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SectionCharacteristic {
    Code,
    InitializedData,
    UninitializedData,
    Discardable,
    NotCached,
    NotPaged,
    Shared,
    Executable,
    Readable,
    Writable,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Magic {
    PE32,
    PE32Plus,
}

#[derive(Debug, PartialEq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
    pub characteristic_flags: Vec<SectionCharacteristic>,
}

impl SectionHeader {
    pub fn name_as_string(&self) -> String {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());

        String::from_utf8_lossy(&self.name[..len]).to_string()
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DataDirectories {
    pub entries: Vec<DataDirectory>,
}

impl DataDirectories {
    pub fn get(&self, directory: DataDirectoryType) -> Option<&DataDirectory> {
        self.entries.get(directory as usize)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(usize)]
pub enum DataDirectoryType {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    ImportAddressTable = 12,
    DelayImport = 13,
    ClrRuntime = 14,
    Reserved = 15,
}

impl DataDirectoryType {
    pub const ALL: [DataDirectoryType; 16] = [
        DataDirectoryType::Export,
        DataDirectoryType::Import,
        DataDirectoryType::Resource,
        DataDirectoryType::Exception,
        DataDirectoryType::Certificate,
        DataDirectoryType::BaseRelocation,
        DataDirectoryType::Debug,
        DataDirectoryType::Architecture,
        DataDirectoryType::GlobalPtr,
        DataDirectoryType::Tls,
        DataDirectoryType::LoadConfig,
        DataDirectoryType::BoundImport,
        DataDirectoryType::ImportAddressTable,
        DataDirectoryType::DelayImport,
        DataDirectoryType::ClrRuntime,
        DataDirectoryType::Reserved,
    ];

    pub fn name(self) -> &'static str {
        match self {
            DataDirectoryType::Export => "Export",
            DataDirectoryType::Import => "Import",
            DataDirectoryType::Resource => "Resource",
            DataDirectoryType::Exception => "Exception",
            DataDirectoryType::Certificate => "Certificate",
            DataDirectoryType::BaseRelocation => "Base Relocation",
            DataDirectoryType::Debug => "Debug",
            DataDirectoryType::Architecture => "Architecture",
            DataDirectoryType::GlobalPtr => "Global Ptr",
            DataDirectoryType::Tls => "TLS",
            DataDirectoryType::LoadConfig => "Load Config",
            DataDirectoryType::BoundImport => "Bound Import",
            DataDirectoryType::ImportAddressTable => "Import Address Table",
            DataDirectoryType::DelayImport => "Delay Import",
            DataDirectoryType::ClrRuntime => "CLR Runtime",
            DataDirectoryType::Reserved => "Reserved",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub first_thunk: u32,
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

    let machine_value = read_u16(data, &mut current_offset)?;
    let machine = interpret_machine(machine_value);
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

    let number_of_rva_and_sizes = match magic {
        Magic::PE32 => {
            let _size_of_stack_reserve = read_u32(optional_header_data, &mut optional_offset)?;
            let _size_of_stack_commit = read_u32(optional_header_data, &mut optional_offset)?;
            let _size_of_heap_reserve = read_u32(optional_header_data, &mut optional_offset)?;
            let _size_of_heap_commit = read_u32(optional_header_data, &mut optional_offset)?;
            let _loader_flags = read_u32(optional_header_data, &mut optional_offset)?;

            read_u32(optional_header_data, &mut optional_offset)?
        }

        Magic::PE32Plus => {
            let _size_of_stack_reserve = read_u64(optional_header_data, &mut optional_offset)?;
            let _size_of_stack_commit = read_u64(optional_header_data, &mut optional_offset)?;
            let _size_of_heap_reserve = read_u64(optional_header_data, &mut optional_offset)?;
            let _size_of_heap_commit = read_u64(optional_header_data, &mut optional_offset)?;
            let _loader_flags = read_u32(optional_header_data, &mut optional_offset)?;

            read_u32(optional_header_data, &mut optional_offset)?
        }
    };

    let data_directories = parse_data_directories(
        optional_header_data,
        &mut optional_offset,
        number_of_rva_and_sizes,
    )?;

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
                data_directories,
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
                data_directories,
            },
            image_base: image_base_64.unwrap(),
        }),
    };

    let mut section_table = current_offset + size_of_optional_header as usize;
    let mut sections = Vec::with_capacity(number_of_sections as usize);

    for _ in 0..number_of_sections {
        let section = parse_section_header(data, &mut section_table)?;
        sections.push(section);
    }

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
        sections,
    })
}

fn parse_data_directories(
    data: &[u8],
    offset: &mut usize,
    count: u32,
) -> Result<DataDirectories, PeError> {
    let mut entries = Vec::with_capacity(16);

    let to_read = count.min(16);

    for _ in 0..to_read {
        entries.push(DataDirectory {
            virtual_address: read_u32(data, offset)?,
            size: read_u32(data, offset)?,
        });
    }

    while entries.len() < 16 {
        entries.push(DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    }

    Ok(DataDirectories { entries })
}

fn parse_import_lookup_table(
    pe: &PeFile,
    data: &[u8],
    thunk_rva: u32,
) -> Result<Vec<String>, PeError> {
    let mut functions = Vec::new();

    let mut offset = pe
        .rva_to_file_offset(thunk_rva)
        .ok_or(PeError::InvalidOffset)? as usize;

    loop {
        let thunk = read_u64(data, &mut offset)?;

        if thunk == 0 {
            break;
        }

        if thunk & 0x8000_0000_0000_0000 != 0 {
            continue;
        }

        let name_offset = pe
            .rva_to_file_offset(thunk as u32)
            .ok_or(PeError::InvalidOffset)? as usize;

        let import = parse_import_by_name(data, name_offset)?;

        functions.push(import.name);
    }

    Ok(functions)
}

fn parse_section_header(data: &[u8], offset: &mut usize) -> Result<SectionHeader, PeError> {
    let name_bytes = checked_range(data, *offset, 8)?;
    let mut name = [0u8; 8];
    name.copy_from_slice(name_bytes);
    *offset += 8;

    let virtual_size = read_u32(data, offset)?;
    let virtual_address = read_u32(data, offset)?;
    let size_of_raw_data = read_u32(data, offset)?;
    let pointer_to_raw_data = read_u32(data, offset)?;
    let pointer_to_relocations = read_u32(data, offset)?;
    let pointer_to_linenumbers = read_u32(data, offset)?;
    let number_of_relocations = read_u16(data, offset)?;
    let number_of_linenumbers = read_u16(data, offset)?;
    let characteristics = read_u32(data, offset)?;
    let characteristic_flags = parse_section_characteristics(characteristics);

    Ok(SectionHeader {
        name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        characteristics,
        characteristic_flags,
    })
}

fn parse_import_descriptor(data: &[u8], offset: &mut usize) -> Result<ImportDescriptor, PeError> {
    Ok(ImportDescriptor {
        original_first_thunk: read_u32(data, offset)?,
        time_date_stamp: read_u32(data, offset)?,
        forwarder_chain: read_u32(data, offset)?,
        name_rva: read_u32(data, offset)?,
        first_thunk: read_u32(data, offset)?,
    })
}

fn read_c_string(data: &[u8], offset: usize) -> Result<String, PeError> {
    let mut end = offset;

    while end < data.len() && data[end] != 0 {
        end += 1;
    }

    if end >= data.len() {
        return Err(PeError::InvalidOffset);
    }

    Ok(String::from_utf8_lossy(&data[offset..end]).to_string())
}

fn parse_import_by_name(data: &[u8], offset: usize) -> Result<ImportByName, PeError> {
    let mut current = offset;

    let hint = read_u16(data, &mut current)?;
    let name = read_c_string(data, current)?;

    Ok(ImportByName { hint, name })
}

fn parse_section_characteristics(value: u32) -> Vec<SectionCharacteristic> {
    let mut flags = Vec::new();

    if value & 0x00000020 != 0 {
        flags.push(SectionCharacteristic::Code);
    }

    if value & 0x00000040 != 0 {
        flags.push(SectionCharacteristic::InitializedData);
    }

    if value & 0x00000080 != 0 {
        flags.push(SectionCharacteristic::UninitializedData);
    }

    if value & 0x02000000 != 0 {
        flags.push(SectionCharacteristic::Discardable);
    }

    if value & 0x04000000 != 0 {
        flags.push(SectionCharacteristic::NotCached);
    }

    if value & 0x08000000 != 0 {
        flags.push(SectionCharacteristic::NotPaged);
    }

    if value & 0x10000000 != 0 {
        flags.push(SectionCharacteristic::Shared);
    }

    if value & 0x20000000 != 0 {
        flags.push(SectionCharacteristic::Executable);
    }

    if value & 0x40000000 != 0 {
        flags.push(SectionCharacteristic::Readable);
    }

    if value & 0x80000000 != 0 {
        flags.push(SectionCharacteristic::Writable);
    }

    flags
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
pub mod tests {
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

    const SECTION_HEADER_SIZE: usize = 40;

    impl Machine {
        fn to_u16(self) -> u16 {
            match self {
                Machine::X86 => 0x014C,
                Machine::AMD64 => 0x8664,
                Machine::Arm => 0x01C0,
                Machine::Arm64 => 0xAA64,
                Machine::Unknown(value) => value,
            }
        }
    }

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
        *curr += 2;
    }

    fn serialize_section_header(curr: &mut usize, buffer: &mut [u8], section: &SectionHeader) {
        buffer[*curr..*curr + 8].copy_from_slice(&section.name);
        *curr += 8;
        buffer[*curr..*curr + 4].copy_from_slice(&section.virtual_size.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&section.virtual_address.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&section.size_of_raw_data.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&section.pointer_to_raw_data.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&section.pointer_to_relocations.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 4].copy_from_slice(&section.pointer_to_linenumbers.to_le_bytes());
        *curr += 4;
        buffer[*curr..*curr + 2].copy_from_slice(&section.number_of_relocations.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 2].copy_from_slice(&section.number_of_linenumbers.to_le_bytes());
        *curr += 2;
        buffer[*curr..*curr + 4].copy_from_slice(&section.characteristics.to_le_bytes());
        *curr += 4;
    }

    fn create_valid_pe_buffer(
        e_lfanew: u32,
        coff_header: &CoffHeader,
        optional_header: Option<&OptionalHeader>,
        sections: &[SectionHeader],
    ) -> Vec<u8> {
        let pe_offset = e_lfanew as usize;
        let opt_size = coff_header.size_of_optional_header as usize;
        let section_size = SECTION_HEADER_SIZE;

        let total_size = pe_offset
            + PE_SIGNATURE_SIZE
            + COFF_HEADER_SIZE
            + opt_size
            + sections.len() * section_size;

        let mut buffer = vec![0u8; total_size];

        // Firma DOS "MZ"
        buffer[0..2].copy_from_slice(&DOS_SIGNATURE);

        // e_lfanew
        buffer[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // Firma PE "PE\0\0"
        buffer[pe_offset..pe_offset + PE_SIGNATURE_SIZE].copy_from_slice(&PE_SIGNATURE);

        // COFF Header (20 bytes)
        let mut curr = pe_offset + PE_SIGNATURE_SIZE;

        buffer[curr..curr + MACHINE_SIZE]
            .copy_from_slice(&coff_header.machine.to_u16().to_le_bytes());
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

                    buffer[curr..curr + 4].copy_from_slice(&0u32.to_le_bytes());
                    curr += 4;
                    // repetir cuatro veces

                    buffer[curr..curr + 4].copy_from_slice(&0u32.to_le_bytes());
                    curr += 4; // LoaderFlags

                    buffer[curr..curr + 4].copy_from_slice(&16u32.to_le_bytes());
                    curr += 4; // NumberOfRvaAndSizes

                    for _ in 0..16 {
                        buffer[curr..curr + 8].fill(0);
                        curr += 8;
                    }
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

                    // SizeOfStackReserve (8 bytes)
                    buffer[curr..curr + 8].copy_from_slice(&0u64.to_le_bytes());
                    curr += 8;

                    // SizeOfStackCommit (8 bytes)
                    buffer[curr..curr + 8].copy_from_slice(&0u64.to_le_bytes());
                    curr += 8;

                    // SizeOfHeapReserve (8 bytes)
                    buffer[curr..curr + 8].copy_from_slice(&0u64.to_le_bytes());
                    curr += 8;

                    // SizeOfHeapCommit (8 bytes)
                    buffer[curr..curr + 8].copy_from_slice(&0u64.to_le_bytes());
                    curr += 8;

                    // LoaderFlags (u32 - 4 bytes)
                    buffer[curr..curr + 4].copy_from_slice(&0u32.to_le_bytes());
                    curr += 4;

                    // NumberOfRvaAndSizes (u32 - 4 bytes)
                    buffer[curr..curr + 4].copy_from_slice(&16u32.to_le_bytes());
                    curr += 4;

                    for _ in 0..16 {
                        buffer[curr..curr + 8].fill(0);
                        curr += 8;
                    }
                }
            }
        }

        for sec in sections {
            serialize_section_header(&mut curr, &mut buffer, sec);
        }

        let mut section_offset = pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE + opt_size;

        for section in sections {
            buffer[section_offset..section_offset + 8].copy_from_slice(&section.name);
            section_offset += 8;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.virtual_size.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.virtual_address.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.size_of_raw_data.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.pointer_to_raw_data.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.pointer_to_relocations.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.pointer_to_linenumbers.to_le_bytes());
            section_offset += 4;

            buffer[section_offset..section_offset + 2]
                .copy_from_slice(&section.number_of_relocations.to_le_bytes());
            section_offset += 2;

            buffer[section_offset..section_offset + 2]
                .copy_from_slice(&section.number_of_linenumbers.to_le_bytes());
            section_offset += 2;

            buffer[section_offset..section_offset + 4]
                .copy_from_slice(&section.characteristics.to_le_bytes());

            section_offset += 4;
        }

        buffer
    }

    pub fn sample_common(magic: Magic) -> OptionalHeaderCommon {
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
            data_directories: DataDirectories {
                entries: vec![
                    DataDirectory {
                        virtual_address: 0,
                        size: 0,
                    };
                    16
                ],
            },
        }
    }

    #[test]
    fn test_valid_pe32_parsing() {
        let coff_header = CoffHeader {
            machine: Machine::X86,
            number_of_sections: 0,
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

        let buffer = create_valid_pe_buffer(0x80, &coff_header, Some(&optional_header), &[]);
        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
                optional_header,
                sections: vec![],
            })
        );
    }

    #[test]
    fn test_valid_pe32plus_parsing() {
        let coff_header = CoffHeader {
            machine: Machine::X86,
            number_of_sections: 0,
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

        let buffer = create_valid_pe_buffer(0x80, &coff_header, Some(&optional_header), &[]);
        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
                optional_header,
                sections: vec![],
            })
        );
    }

    #[test]
    fn test_parsing_with_sections() {
        let coff_header = CoffHeader {
            machine: Machine::X86,
            number_of_sections: 1,
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
        let sections = vec![SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x60000020,
            characteristic_flags: vec![
                SectionCharacteristic::Code,
                SectionCharacteristic::Executable,
                SectionCharacteristic::Readable,
            ],
        }];

        let buffer = create_valid_pe_buffer(0x80, &coff_header, Some(&optional_header), &sections);

        let result = parse(&buffer);

        assert_eq!(
            result,
            Ok(PeFile {
                e_lfanew: 0x80,
                coff_header,
                optional_header,
                sections,
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
            machine: Machine::X86,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00E0,
            characteristics: 0,
        };

        let mut buffer = create_valid_pe_buffer(0x80, &coff_header, None, &[]);
        buffer[0x80..0x84].copy_from_slice(b"FAIL");
        assert_eq!(parse(&buffer), Err(PeError::InvalidPeSignature));
    }

    #[test]
    fn test_invalid_magic() {
        let coff_header = CoffHeader {
            machine: Machine::X86,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0x00E0,
            characteristics: 0,
        };

        let mut buffer = create_valid_pe_buffer(0x80, &coff_header, None, &[]);
        let opt_start = 0x80 + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE;
        buffer[opt_start..opt_start + 2].copy_from_slice(&0x9999u16.to_le_bytes());

        assert_eq!(parse(&buffer), Err(PeError::InvalidMagic));
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

    #[test]
    fn test_section_name_as_string() {
        let section = SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
            characteristic_flags: vec![],
        };

        assert_eq!(section.name_as_string(), ".text");
    }

    #[test]
    fn test_section_names() {
        let pe = PeFile {
            e_lfanew: 0x80,
            coff_header: CoffHeader {
                machine: Machine::X86,
                number_of_sections: 2,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0xF0,
                characteristics: 0x22,
            },
            optional_header: OptionalHeader::PE32Plus(OptionalHeader64 {
                common: sample_common(Magic::PE32Plus),
                image_base: 0x140000000,
            }),
            sections: vec![
                SectionHeader {
                    name: *b".text\0\0\0",
                    virtual_size: 0,
                    virtual_address: 0,
                    size_of_raw_data: 0,
                    pointer_to_raw_data: 0,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0,
                    characteristic_flags: vec![],
                },
                SectionHeader {
                    name: *b".rdata\0\0",
                    virtual_size: 0,
                    virtual_address: 0,
                    size_of_raw_data: 0,
                    pointer_to_raw_data: 0,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0,
                    characteristic_flags: vec![],
                },
            ],
        };

        assert_eq!(
            pe.section_names(),
            vec![".text".to_string(), ".rdata".to_string()]
        );
    }

    #[test]
    fn test_empty_data_directories() {
        let dirs = DataDirectories {
            entries: vec![
                DataDirectory {
                    virtual_address: 0,
                    size: 0,
                };
                16
            ],
        };

        assert_eq!(dirs.entries.len(), 16);

        assert_eq!(
            dirs.get(DataDirectoryType::Import),
            Some(&DataDirectory {
                virtual_address: 0,
                size: 0,
            })
        );
    }
    #[test]
    fn test_rva_to_file_offset() {
        let pe = PeFile {
            e_lfanew: 0x80,

            coff_header: CoffHeader {
                machine: Machine::X86,
                number_of_sections: 1,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0xF0,
                characteristics: 0x22,
            },

            optional_header: OptionalHeader::PE32Plus(OptionalHeader64 {
                common: sample_common(Magic::PE32Plus),
                image_base: 0x140000000,
            }),

            sections: vec![SectionHeader {
                name: *b".text\0\0\0",
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                size_of_raw_data: 0x1000,
                pointer_to_raw_data: 0x400,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0x60000020,
                characteristic_flags: vec![
                    SectionCharacteristic::Code,
                    SectionCharacteristic::Executable,
                    SectionCharacteristic::Readable,
                ],
            }],
        };

        assert_eq!(pe.rva_to_file_offset(0x1234), Some(0x634));
    }

    #[test]
    fn test_get_import_directory() {
        let mut entries = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];

        entries[DataDirectoryType::Import as usize] = DataDirectory {
            virtual_address: 0x3000,
            size: 0x120,
        };

        let directories = DataDirectories { entries };

        assert_eq!(
            directories.get(DataDirectoryType::Import),
            Some(&DataDirectory {
                virtual_address: 0x3000,
                size: 0x120,
            })
        );
    }

    #[test]
    fn test_read_c_string() {
        let data = b"KERNEL32.dll\0extra";

        assert_eq!(read_c_string(data, 0), Ok("KERNEL32.dll".to_string()));
    }

    #[test]
    fn test_parse_import_by_name() {
        let data = [
            0x34, 0x12, b'L', b'o', b'a', b'd', b'L', b'i', b'b', b'r', b'a', b'r', b'y', b'W',
            0x00,
        ];

        let import = parse_import_by_name(&data, 0).unwrap();

        assert_eq!(import.hint, 0x1234);
        assert_eq!(import.name, "LoadLibraryW");
    }
}
