use crate::analysis::detector::analyze_imports;
use crate::analysis::detector::analyze_sections;
use crate::analysis::entropy::analyze_entropy;
use crate::analysis::findings::AnalysisResult;
use crate::pe::PeError;
use crate::pe::PeFile;

pub fn analyze(pe: &PeFile, data: &[u8]) -> Result<AnalysisResult, PeError> {
    let imported_dlls = pe.imported_dlls(data);
    let mut accumulated_findings = Vec::new();
    let mut accumulated_score: u8 = 0;

    match imported_dlls {
        Ok(modules) => {
            let mut import_result = analyze_imports(&modules);
            accumulated_findings.append(&mut import_result.findings);
            accumulated_score += import_result.score;

            let mut entropy_result = analyze_entropy(pe, data);
            accumulated_findings.append(&mut entropy_result.findings);
            accumulated_score += entropy_result.score;

            let mut sections_result = analyze_sections(pe);
            accumulated_findings.append(&mut sections_result.findings);
            accumulated_score += sections_result.score;

            let final_result = AnalysisResult {
                score: accumulated_score,
                findings: accumulated_findings,
            };
            Ok(final_result)
        }
        Err(error) => Err(error),
    }
}
