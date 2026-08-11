mod binary;
mod binary_file;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Use: cargo run -- <ruta_del_archivo>");
        return;
    }

    match binary_file::load_file(&args[1]) {
        Ok(binary_file) => {
            let format = binary::detect_format(&binary_file.data);
            println!("{:?}", format);
            println!("The path is {}", binary_file.path);
        }

        Err(error) => {
            eprintln!("Error reading the file: {}", error);
        }
    }
}
