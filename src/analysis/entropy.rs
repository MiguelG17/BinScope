use crate::analysis::findings::{Finding, Severity};
use crate::pe::PeFile;

pub fn calculate_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequency = [0usize; 256];

    for &byte in bytes {
        frequency[byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;

    for count in frequency {
        if count == 0 {
            continue;
        }

        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

pub fn analyze_entropy(pe: &PeFile, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        let Some(end) = start.checked_add(size) else {
            continue;
        };

        if end > data.len() {
            continue;
        }

        let entropy = calculate_entropy(&data[start..end]);

        if entropy >= 7.2 {
            findings.push(Finding {
                name: "High Entropy Section",
                severity: Severity::Medium,
                score: 20,
                evidence: vec![format!("{} ({:.2})", section.name_as_string(), entropy)],
                missing: vec![],
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_zero_for_uniform_data() {
        let bytes = vec![0u8; 100];

        assert_eq!(calculate_entropy(&bytes), 0.0);
    }

    #[test]
    fn entropy_high_for_all_byte_values() {
        let bytes: Vec<u8> = (0u8..=255).collect();

        let entropy = calculate_entropy(&bytes);

        assert!(entropy > 7.9);
    }

    #[test]
    fn entropy_empty_slice() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }
}
