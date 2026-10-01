use super::findings::Severity;

#[derive(Debug)]
pub struct Rule {
    pub name: &'static str,
    pub severity: Severity,
    pub score: u8,
    pub apis: &'static [&'static str],
}

pub const RULES: &[Rule] = &[
    Rule {
        name: "Process Injection",
        severity: Severity::High,
        score: 40,
        apis: &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
    },
    Rule {
        name: "Registry Access",
        severity: Severity::Medium,
        score: 20,
        apis: &["RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW"],
    },
    Rule {
        name: "Network Communication",
        severity: Severity::Medium,
        score: 28,
        apis: &["InternetOpenW", "InternetConnectW", "HttpSendRequestW"],
    },
    Rule {
        name: "File Operations",
        severity: Severity::Low,
        score: 8,
        apis: &["CreateFileW", "ReadFile", "WriteFile"],
    },
];
