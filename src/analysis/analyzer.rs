use crate::analysis::detector::analyze_imports;
use crate::analysis::detector::analyze_sections;
use crate::analysis::entropy::analyze_entropy;
use crate::analysis::findings::AnalysisResult;
use crate::pe::PeFile;

pub fn analyze(pe: &PeFile, data: &[u8]) -> AnalysisResult {
    let imported_dlls = pe.imported_dlls(data);
    let mut accumulated_findings = Vec::new();
    let mut accumulated_score: u8 = 0;

    if let Ok(modules) = imported_dlls {
        let mut import_result = analyze_imports(&modules);
        accumulated_findings.append(&mut import_result.findings);
        accumulated_score = accumulated_score.saturating_add(import_result.score);
    }

    let mut entropy_result = analyze_entropy(pe, data);
    accumulated_findings.append(&mut entropy_result.findings);
    accumulated_score = accumulated_score.saturating_add(entropy_result.score);

    let mut sections_result = analyze_sections(pe);
    accumulated_findings.append(&mut sections_result.findings);
    accumulated_score = accumulated_score.saturating_add(sections_result.score);

    AnalysisResult {
        score: accumulated_score.min(100),
        findings: accumulated_findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::tests::sample_common;
    use crate::pe::{CoffHeader, Machine, Magic, OptionalHeader, OptionalHeader64, PeFile};

    #[test]
    fn test_analyze_handles_empty_data() {
        let pe = PeFile {
            e_lfanew: 0,
            coff_header: CoffHeader {
                machine: Machine::AMD64,
                number_of_sections: 1,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional_header: OptionalHeader::PE32Plus(OptionalHeader64 {
                common: sample_common(Magic::PE32Plus),
                image_base: 0x140000000,
            }),
            sections: vec![],
        };

        let result = analyze(&pe, &[]);

        assert_eq!(result.score, 0);
    }
}
