mod binary;

fn main() {
    let data = [0x4D, 0x5A];

    let format = binary::detect_format(&data);

    println!("{:?}", format);
}
