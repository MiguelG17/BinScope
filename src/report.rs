use crate::pe::{OptionalHeader, PeFile};

pub fn print_pe_report(pe: &PeFile) {
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
}

fn print_optional_header(pe: &PeFile) {
    match &pe.optional_header {
        OptionalHeader::PE32(header) => {
            println!("Format: PE32");
            println!("Image Base: 0x{:08X}", header.image_base);
            println!(
                "Entry Point: 0x{:08X}",
                header.common.address_of_entry_point
            );
        }

        OptionalHeader::PE32Plus(header) => {
            println!("Format: PE32+");
            println!("Image Base: 0x{:016X}", header.image_base);
            println!(
                "Entry Point: 0x{:08X}",
                header.common.address_of_entry_point
            );
        }
    }
}