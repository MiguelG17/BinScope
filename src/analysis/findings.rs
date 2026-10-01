#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub name: &'static str,
    pub severity: Severity,
    pub score: u8,
    pub evidence: Vec<String>, //Discover APIs
    pub missing: Vec<String>,
}

pub struct AnalysisResult {
    pub score: u8,
    pub findings: Vec<Finding>,
}

impl AnalysisResult {
    pub fn risk_level(&self) -> &'static str {
        match self.score {
            0..=19 => "Minimal",
            20..=39 => "Low",
            40..=69 => "Medium",
            70..=89 => "High",
            _ => "Critical",
        }
    }
}
