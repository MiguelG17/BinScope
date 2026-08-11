use std::fs;
#[derive(Debug)]
pub struct BinaryFile {
    pub path: String,
    pub data: Vec<u8>,
}

pub fn load_file(path: &str) -> Result<BinaryFile, std::io::Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(BinaryFile {
            path: path.to_string(),
            data: bytes,
        }),
        Err(error) => {
            eprintln!("Error reading the file: {}", error);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_file_success() {
        let mut file = tempfile::NamedTempFile::new().unwrap();

        let test_data = vec![1, 2, 3, 4, 5];

        file.write_all(&test_data).unwrap();

        let resultado = load_file(file.path().to_str().unwrap());

        assert!(resultado.is_ok());

        let binary_file = resultado.unwrap();

        assert_eq!(binary_file.data, test_data);
    }

    #[test]
    fn test_load_file_not_found() {
        let ruta_inexistente = "file_not_exist.bin";

        let resultado = load_file(ruta_inexistente);

        assert!(
            resultado.is_err(),
            "It should fail because the file does not exist."
        );

        let error = resultado.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
