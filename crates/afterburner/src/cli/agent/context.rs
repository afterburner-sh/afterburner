// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Managed instruction block for assistants that read a memory/instructions
//! markdown file (Claude Code's `CLAUDE.md`, Gemini's `GEMINI.md`, Codex's
//! `AGENTS.md`). The hook is the enforcement; this block is the teaching -
//! with it the assistant reaches for `burn` proactively instead of learning
//! by denial. Fenced by HTML-comment sentinels so install/uninstall splice
//! it without touching the user's own notes.

use std::path::{Path, PathBuf};

const SENTINEL_START: &str = "<!-- >>> burn agent (managed) >>> -->";
const SENTINEL_END: &str = "<!-- <<< burn agent (managed) <<< -->";

/// The instruction block body (between the sentinels).
const BLOCK_BODY: &str = "## Code execution\n\
Run ALL code SEALED in the burn sandbox (no network, filesystem, or env by default).\n\
Python: `burn x.py`  Ruby: `burn x.rb`  JS/TS: `burn node x.js` or `burn x.ts`\n\
Rust/Go/C/C++: `burn x.rs` / `burn x.go` / `burn x.c` / `burn x.cpp`\n\
Inline JS only: `burn --sandbox -e '<code>'`.\n\
Grant capabilities narrowly when genuinely required, e.g. `--allow-net=api.example.com`\n\
or `--allow-fs-read=./data`. Never use `--allow-all`.";

/// The memory file a host reads, or `None` for hosts that have no plain
/// markdown instruction file (Cursor, Copilot - their hook reason carries
/// the guidance instead).
fn context_path(key: &str, user: bool) -> Option<PathBuf> {
    let home = || PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
    let cwd = || std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match (key, user) {
        ("claude-code", true) => Some(home().join(".claude").join("CLAUDE.md")),
        ("claude-code", false) => Some(cwd().join("CLAUDE.md")),
        // agy parses the same GEMINI.md files as Gemini CLI; the managed
        // block is identical and sentinel-keyed, so installing for both
        // hosts refreshes rather than duplicates. (Uninstalling either
        // removes the shared block - re-run install for the one you keep.)
        ("gemini" | "antigravity", true) => Some(home().join(".gemini").join("GEMINI.md")),
        ("gemini" | "antigravity", false) => Some(cwd().join("GEMINI.md")),
        ("codex", true) => Some(home().join(".codex").join("AGENTS.md")),
        ("codex", false) => Some(cwd().join("AGENTS.md")),
        _ => None,
    }
}

/// Remove the inclusive sentinel region (and one preceding blank line) if
/// present; otherwise return the text unchanged.
fn strip_block(text: &str) -> String {
    let (Some(s), Some(e)) = (text.find(SENTINEL_START), text.find(SENTINEL_END)) else {
        return text.to_string();
    };
    if e < s {
        return text.to_string();
    }
    let region_end = text[e..].find('\n').map_or(text.len(), |nl| e + nl + 1);
    let mut out = text[..s].trim_end_matches('\n').to_string();
    out.push_str(&text[region_end..]);
    out
}

/// Append (or refresh in place) the managed block in `path`.
fn write_block(path: &Path) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let present = existing.contains(SENTINEL_START);
    let base = strip_block(&existing);
    let sep = if base.trim().is_empty() { "" } else { "\n" };
    let body = format!(
        "{}{sep}\n{SENTINEL_START}\n{BLOCK_BODY}\n{SENTINEL_END}\n",
        base.trim_end_matches('\n')
    );
    std::fs::write(path, body)?;
    let verb = if present { "refreshed" } else { "added" };
    Ok(format!("+ {verb} instructions -> {}", path.display()))
}

/// Install the instruction block for a host. Returns `None` for hosts
/// without a markdown instruction file.
///
/// # Errors
/// Propagates I/O failure.
pub fn install_context(key: &str, user: bool) -> std::io::Result<Option<String>> {
    match context_path(key, user) {
        Some(path) => write_block(&path).map(Some),
        None => Ok(None),
    }
}

/// Remove the instruction block for a host (the inverse of
/// [`install_context`]).
///
/// # Errors
/// Propagates write I/O failure.
pub fn remove_context(key: &str, user: bool) -> std::io::Result<Option<String>> {
    let Some(path) = context_path(key, user) else {
        return Ok(None);
    };
    let Ok(existing) = std::fs::read_to_string(&path) else {
        return Ok(Some(format!("= nothing to remove: {}", path.display())));
    };
    let base = strip_block(&existing);
    if base == existing {
        return Ok(Some(format!("= no managed block in {}", path.display())));
    }
    if base.trim().is_empty() {
        // The file was only our block: remove it entirely.
        std::fs::remove_file(&path)?;
        return Ok(Some(format!(
            "- removed instructions <- {}",
            path.display()
        )));
    }
    // Splicing the tail block trims the file's final newline; restore it.
    let body = if base.ends_with('\n') {
        base
    } else {
        base + "\n"
    };
    std::fs::write(&path, body)?;
    Ok(Some(format!(
        "- removed instructions <- {}",
        path.display()
    )))
}

/// Whether the managed block is present in the host's instruction file.
#[must_use]
pub fn context_present(key: &str, user: bool) -> bool {
    context_path(key, user)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|t| t.contains(SENTINEL_START))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trip_preserves_user_notes() {
        let dir = std::env::temp_dir().join(format!("burn-agent-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("CLAUDE.md");
        std::fs::write(&path, "# My notes\n\nKeep these.\n").unwrap();

        write_block(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# My notes"));
        assert!(text.contains(SENTINEL_START));
        assert!(text.contains("burn x.py"));

        // Refresh in place: one block, never two.
        write_block(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(SENTINEL_START).count(), 1);

        // Strip restores the user's file.
        let stripped = strip_block(&text);
        assert!(stripped.contains("# My notes"));
        assert!(!stripped.contains(SENTINEL_START));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_file_contains_only_the_block_and_is_deleted_on_remove() {
        let dir = std::env::temp_dir().join(format!("burn-agent-ctxf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("AGENTS.md");

        write_block(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.trim_start().starts_with(SENTINEL_START));

        // remove_context's "file was only our block" path.
        let base = strip_block(&text);
        assert!(base.trim().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
