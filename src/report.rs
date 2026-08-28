use crate::pe::{DataDirectories, DataDirectoryType, OptionalHeader, PeFile};
fn print_optional_header(pe: &PeFile) {
    match &pe.optional_header {
        OptionalHeader::PE32(header) => {
            println!("Format: PE32");
            println!("Image Base: 0x{:08X}", header.image_base);
            println!(
                "Entry Point: 0x{:08X}",
                header.common.address_of_entry_point
            );

            print_data_directories(&header.common.data_directories);
        }

        OptionalHeader::PE32Plus(header) => {
            println!("Format: PE32+");
            println!("Image Base: 0x{:016X}", header.image_base);
            println!(
                "Entry Point: 0x{:08X}",
                header.common.address_of_entry_point
            );

            print_data_directories(&header.common.data_directories);
        }
    }
}

pub fn print_pe_report(pe: &PeFile, data: &[u8]) {
    println!("PE Analysis");
    println!("===========");

    println!("Machine: {:?}", pe.coff_header.machine);
    println!("Sections: {}", pe.sections.len());

    println!();
    println!("Sections");
    println!("--------");

    for section_name in pe.section_names() {
        println!("  - {}", section_name);
    }

    println!();
    print_optional_header(pe);
    println!();
    println!("Imports");
    println!("-------");

    match pe.imported_dlls(data) {
        Ok(dlls) => {
            for module in dlls {
                println!("  {}", module.dll_name);

                for function in module.functions {
                    println!("      {}", function);
                }

                println!();
            }
        }
        Err(_) => println!("Unable to read imports."),
    }
}

fn print_data_directories(directories: &DataDirectories) {
    println!("\nData Directories");
    println!("----------------");

    for directory in DataDirectoryType::ALL {
        if let Some(entry) = directories.get(directory)
            && (entry.virtual_address != 0 || entry.size != 0)
        {
            println!(
                "{:<20} RVA: 0x{:08X}  Size: {}",
                directory.name(),
                entry.virtual_address,
                entry.size
            );
        }
    }
}
