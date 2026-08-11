mod binary;

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Use: cargo run -- <ruta_del_archivo>");
        return;
    }

    match fs::read(&args[1]) {
        Ok(bytes) => {
            let format = binary::detect_format(&bytes);
            println!("{:?}", format);
        }
        Err(error) => {
            eprintln!("Error reading the file: {}", error);
        }
    }
}