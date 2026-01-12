//! File utilities

use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

/// Discover files to scan in a directory
pub fn discover_files(path: &Path, exclude_patterns: &[String]) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let path = entry.path();

            // Check exclude patterns
            let path_str = path.to_string_lossy();
            if exclude_patterns
                .iter()
                .any(|pattern| path_str.contains(pattern))
            {
                continue;
            }

            // Only scan text files (Python, JavaScript, TypeScript, etc.)
            if let Some(ext) = path.extension() {
                match ext.to_str() {
                    Some("py") | Some("js") | Some("ts") | Some("jsx") | Some("tsx")
                    | Some("json") | Some("yaml") | Some("yml") => {
                        files.push(path.to_path_buf());
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(files)
}

/// Read file contents as string
pub fn read_file(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_files_empty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = discover_files(temp_dir.path(), &[]).unwrap();
        assert_eq!(files.len(), 0);
    }
}
