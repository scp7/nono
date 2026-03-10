use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
struct NetworkPolicy {
    allow_domains: Vec<String>,
    block_content_types: Vec<String>,
}

impl NetworkPolicy {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        let policy: Self = serde_json::from_reader(file)?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_policy_parsing() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("policy.json");
        let policy_json = r#"{
            "allow_domains": ["*.example.com", "safe-site.org"],
            "block_content_types": ["image/*", "application/javascript"]
        }"#;
        
        fs::write(&file_path, policy_json).unwrap();
        let policy = NetworkPolicy::load(&file_path).unwrap();
        assert_eq!(policy.allow_domains.len(), 2);
        assert_eq!(policy.block_content_types.len(), 2);
    }
}