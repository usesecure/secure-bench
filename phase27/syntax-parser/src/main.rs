//! Neutral tree-sitter syntax validation for frozen Phase 27 source fixtures.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Parser};

#[derive(Serialize)]
struct Receipt {
    schema_version: &'static str,
    parser: &'static str,
    status: &'static str,
    files_parsed: usize,
    javascript: usize,
    jsx: usize,
    typescript: usize,
    tsx: usize,
    inventory_sha256: String,
    case_executions: u8,
    scanner_executions: u8,
}

fn collect_sources(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            collect_sources(&path, output)?;
        } else if kind.is_file()
            && matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("js" | "jsx" | "ts" | "tsx")
            )
        {
            output.push(path);
        }
    }
    Ok(())
}

fn language_for(extension: &str) -> Result<Language, String> {
    match extension {
        "js" | "jsx" => Ok(tree_sitter_javascript::LANGUAGE.into()),
        "ts" => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Ok(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => Err(format!("unsupported extension: {extension}")),
    }
}

fn run(corpus: &Path, output: &Path) -> Result<Receipt, String> {
    let mut files = Vec::new();
    collect_sources(corpus, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err("no source fixtures found".to_owned());
    }
    let mut inventory = BTreeMap::new();
    let mut counts = BTreeMap::<String, usize>::new();
    for path in &files {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .ok_or_else(|| format!("missing extension: {}", path.display()))?;
        let source = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut parser = Parser::new();
        parser
            .set_language(&language_for(extension)?)
            .map_err(|error| error.to_string())?;
        let tree = parser
            .parse(&source, None)
            .ok_or_else(|| format!("parser returned no tree: {}", path.display()))?;
        if tree.root_node().has_error() {
            return Err(format!("syntax error: {}", path.display()));
        }
        let relative = path
            .strip_prefix(corpus)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        inventory.insert(relative, hex_digest(Sha256::digest(&source)));
        *counts.entry(extension.to_owned()).or_default() += 1;
    }
    let inventory_bytes = serde_json::to_vec(&inventory).map_err(|error| error.to_string())?;
    let receipt = Receipt {
        schema_version: "secure-bench-phase27-syntax-v2",
        parser: "tree-sitter-neutral",
        status: "passed-before-freeze",
        files_parsed: files.len(),
        javascript: *counts.get("js").unwrap_or(&0),
        jsx: *counts.get("jsx").unwrap_or(&0),
        typescript: *counts.get("ts").unwrap_or(&0),
        tsx: *counts.get("tsx").unwrap_or(&0),
        inventory_sha256: hex_digest(Sha256::digest(inventory_bytes)),
        case_executions: 0,
        scanner_executions: 0,
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(output, bytes).map_err(|error| format!("{}: {error}", output.display()))?;
    Ok(receipt)
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut text = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        eprintln!("usage: phase27-neutral-parser CORPUS OUTPUT");
        std::process::exit(2);
    }
    match run(Path::new(&arguments[1]), Path::new(&arguments[2])) {
        Ok(receipt) => println!(
            "parsed={} js={} jsx={} ts={} tsx={}",
            receipt.files_parsed, receipt.javascript, receipt.jsx, receipt.typescript, receipt.tsx
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::language_for;

    #[test]
    fn supports_all_frozen_source_formats() {
        for extension in ["js", "jsx", "ts", "tsx"] {
            assert!(language_for(extension).is_ok());
        }
    }

    #[test]
    fn rejects_unknown_source_formats() {
        assert!(language_for("mjs").is_err());
    }
}
