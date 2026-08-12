mod binary;
mod binary_file;
mod pe;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Use: cargo run -- <ruta_del_archivo>");
        return;
    }

    match binary_file::load_file(&args[1]) {
        Ok(binary_file) => {
            println!("The path is {}", binary_file.path);

            let format = binary::detect_format(&binary_file.data);

            println!("Format: {:?}", format);

            if matches!(format, binary::BinaryFormat::Pe) {
                match pe::parse(&binary_file.data) {
                    Ok(pe_file) => {
                        println!("PE parsed successfully");
                        println!("{:#?}", pe_file);
                    }
                    Err(error) => {
                        eprintln!("PE parsing error: {:?}", error);
                    }
                }
            }
        }

        Err(error) => {
            eprintln!("Error reading the file: {}", error);
        }
    }
}
