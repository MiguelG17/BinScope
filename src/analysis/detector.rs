use crate::analysis::entropy::analyze_entropy;
use crate::pe::ImportModule;
use std::collections::HashSet;

use super::{
    findings::{AnalysisResult, Finding, Severity},
    rules::RULES,
};
use crate::pe::{PeFile, SectionCharacteristic};

pub fn analyze_pe(pe: &PeFile, modules: &[ImportModule], data: &[u8]) -> AnalysisResult {
    let mut findings = analyze_imports(modules).findings;

    findings.extend(analyze_sections(pe));
    findings.extend(analyze_entropy(pe, data));

    let score = findings
        .iter()
        .map(|finding| finding.score)
        .sum::<u8>()
        .min(100);

    AnalysisResult { score, findings }
}
pub fn analyze_imports(modules: &[ImportModule]) -> AnalysisResult {
    let imported: HashSet<&str> = modules
        .iter()
        .flat_map(|module| module.functions.iter())
        .map(String::as_str)
        .collect();

    let mut findings = Vec::new();

    for rule in RULES {
        let matched: Vec<String> = rule
            .apis
            .iter()
            .filter(|api| imported.contains(**api))
            .map(|api| api.to_string())
            .collect();

        let missing_list: Vec<String> = rule
            .apis
            .iter()
            .filter(|api| !imported.contains(**api))
            .map(|api| api.to_string())
            .collect();

        if matched.len() >= 2 {
            findings.push(Finding {
                name: rule.name,
                severity: rule.severity,
                score: ((rule.score as usize * matched.len()) / rule.apis.len()) as u8,
                evidence: matched,
                missing: missing_list,
            });
        }
    }

    let score = findings.iter().map(|f| f.score).sum::<u8>().min(100);

    AnalysisResult { score, findings }
}

fn analyze_sections(pe: &PeFile) -> Vec<Finding> {
    let mut findings = Vec::new();

    for section in &pe.sections {
        let executable = section
            .characteristic_flags
            .contains(&SectionCharacteristic::Executable);

        let writable = section
            .characteristic_flags
            .contains(&SectionCharacteristic::Writable);

        if executable && writable {
            findings.push(Finding {
                name: "RWX Section",
                severity: Severity::High,
                score: 35,
                evidence: vec![section.name_as_string()],
                missing: vec![],
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::tests::sample_common;
    use crate::pe::{
        CoffHeader, ImportModule, Machine, Magic, OptionalHeader, OptionalHeader64, SectionHeader,
    };

    #[test]
    fn detects_process_injection() {
        let modules = vec![ImportModule {
            name: "KERNEL32.dll".into(),
            functions: vec![
                "VirtualAlloc".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
            ],
        }];
        let analysis = analyze_imports(&modules);

        assert_eq!(analysis.score, 40);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].name, "Process Injection");
    }

    #[test]
    fn detects_process_injection_partial() {
        let modules = vec![ImportModule {
            name: "KERNEL32.dll".into(),
            functions: vec!["WriteProcessMemory".into(), "CreateRemoteThread".into()],
        }];
        let analysis = analyze_imports(&modules);

        assert_eq!(analysis.score, 26);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(
            !analysis.findings[0].evidence[0].contains("VirtualAlloc"),
            true
        );
        assert_eq!(analysis.findings[0].missing.len(), 1);
        assert_eq!(analysis.findings[0].evidence.len(), 2);
        assert_eq!(analysis.findings[0].name, "Process Injection");
    }

    #[test]
    fn detects_process_injection_partial_no_missing() {
        let modules = vec![ImportModule {
            name: "KERNEL32.dll".into(),
            functions: vec![
                "VirtualAlloc".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
            ],
        }];
        let analysis = analyze_imports(&modules);

        assert_eq!(analysis.score, 40);
        assert_eq!(analysis.findings.len(), 1);
        assert!(analysis.findings[0].missing.is_empty());
        assert_eq!(analysis.findings[0].evidence.len(), 3);
    }

    #[test]
    fn detects_registry_access() {
        let modules = vec![ImportModule {
            name: "ADVAPI32.dll".into(),
            functions: vec![
                "RegOpenKeyExW".into(),
                "RegSetValueExW".into(),
                "RegCreateKeyExW".into(),
            ],
        }];

        let analysis = analyze_imports(&modules);
        assert_eq!(analysis.score, 20);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].name, "Registry Access");
    }

    #[test]
    fn detects_file_operations() {
        let modules = vec![ImportModule {
            name: "KERNEL32.dll".into(),
            functions: vec!["CreateFileW".into(), "ReadFile".into(), "WriteFile".into()],
        }];

        let analysis = analyze_imports(&modules);
        assert_eq!(analysis.score, 8);
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].name, "File Operations");
    }
    #[test]
    fn detects_rwx_section() {
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
            sections: vec![SectionHeader {
                name: *b".evil\0\0\0",
                virtual_size: 0,
                virtual_address: 0,
                size_of_raw_data: 0,
                pointer_to_raw_data: 0,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0xE0000020,
                characteristic_flags: vec![
                    SectionCharacteristic::Executable,
                    SectionCharacteristic::Readable,
                    SectionCharacteristic::Writable,
                ],
            }],
        };

        let modules = vec![];

        let analysis = analyze_pe(&pe, &modules, &[]);

        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].name, "RWX Section");
        assert_eq!(analysis.score, 35);
    }
}
