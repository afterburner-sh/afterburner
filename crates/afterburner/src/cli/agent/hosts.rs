// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Per-assistant hook wiring - idempotently merge (and cleanly remove) the
//! `burn agent hook` pre-tool hook in each AI assistant's config file.
//!
//! Every supported host exposes a blocking pre-tool hook driven by an
//! external command over a `stdin JSON -> stdout decision` contract:
//!
//! | Host         | Config                          | Event                  |
//! |--------------|---------------------------------|------------------------|
//! | Claude Code  | `~/.claude/settings.json`       | `PreToolUse`           |
//! | OpenAI Codex | `~/.codex/config.toml`          | `[[hooks.PreToolUse]]` |
//! | Gemini CLI   | `~/.gemini/settings.json`       | `BeforeTool`           |
//! | Cursor       | `~/.cursor/hooks.json`          | `beforeShellExecution` |
//! | Copilot CLI  | `~/.copilot/hooks/burn.json`    | `preToolUse`           |
//! | Antigravity  | `~/.gemini/config/hooks.json`   | `PreToolUse` (named group) |
//!
//! The hook command bakes in **this binary's absolute path** (not the bare
//! name) so the assistant can spawn it regardless of `PATH`. Idempotence
//! and uninstall both key off the [`MARKER`] substring in the serialized
//! entry; user config around our entries is never touched, and a malformed
//! file is reported and left unchanged rather than clobbered.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The substring that identifies our entries in any host config - the
/// uninstall filter and the duplicate-suppression check both match on it.
pub const MARKER: &str = "burn agent hook";

/// One supported assistant: stable key, friendly label, PATH binary names,
/// and its config dir under `$HOME` (used for detection).
pub struct HostSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub bins: &'static [&'static str],
    pub config_dir: &'static str,
}

/// The assistants `burn agent` knows how to wire.
pub const HOSTS: &[HostSpec] = &[
    HostSpec {
        key: "claude-code",
        label: "Claude Code",
        bins: &["claude"],
        config_dir: ".claude",
    },
    HostSpec {
        key: "codex",
        label: "OpenAI Codex",
        bins: &["codex"],
        config_dir: ".codex",
    },
    HostSpec {
        key: "gemini",
        label: "Gemini CLI",
        bins: &["gemini"],
        config_dir: ".gemini",
    },
    HostSpec {
        key: "cursor",
        label: "Cursor",
        bins: &["cursor", "cursor-agent"],
        config_dir: ".cursor",
    },
    HostSpec {
        key: "copilot",
        label: "GitHub Copilot",
        bins: &["copilot"],
        config_dir: ".copilot",
    },
    HostSpec {
        key: "antigravity",
        label: "Antigravity (agy)",
        bins: &["agy"],
        config_dir: ".gemini/config",
    },
];

/// Look up a host by key.
pub fn spec(key: &str) -> Option<&'static HostSpec> {
    HOSTS.iter().find(|h| h.key == key)
}

/// The absolute path of the running `burn` binary, baked into the hook
/// command. Falls back to the bare name if the exe path can't be resolved.
#[must_use]
pub fn self_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(ToString::to_string))
        .unwrap_or_else(|| "burn".to_string())
}

fn home() -> PathBuf {
    #[cfg(windows)]
    let var = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"));
    #[cfg(not(windows))]
    let var = std::env::var("HOME");
    PathBuf::from(var.unwrap_or_else(|_| ".".to_string()))
}

/// Whether `bin` is on `$PATH` (handles a `.exe` suffix on Windows).
fn on_path(bin: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths)
        .any(|dir| dir.join(bin).is_file() || dir.join(format!("{bin}.exe")).is_file())
}

/// Whether an assistant looks installed: its binary is on `$PATH`, or its
/// config dir already exists under `$HOME`.
#[must_use]
pub fn is_installed(h: &HostSpec) -> bool {
    h.bins.iter().any(|b| on_path(b)) || home().join(h.config_dir).is_dir()
}

/// Where a host's hook config lives. `user=false` targets the project's
/// config for hosts that support repo-local hooks (Claude Code, Gemini);
/// the rest are user-scoped only.
fn config_path(key: &str, user: bool) -> PathBuf {
    let base = if user {
        home()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };
    match key {
        "claude-code" => base.join(".claude").join("settings.json"),
        "gemini" => base.join(".gemini").join("settings.json"),
        // Codex/Cursor/Copilot hooks only fire from user scope.
        "codex" => home().join(".codex").join("config.toml"),
        "cursor" => home().join(".cursor").join("hooks.json"),
        "copilot" => home().join(".copilot").join("hooks").join("burn.json"),
        "antigravity" => home().join(".gemini").join("config").join("hooks.json"),
        _ => base.join(".burn-agent-unknown"),
    }
}

/// The hook command for a host, with the absolute binary path baked in.
fn hook_command(key: &str) -> String {
    format!("{} agent hook --host {key}", self_path())
}

// ── JSON hosts (Claude Code / Gemini) ────────────────────────────────────────

/// Idempotently merge a `{matcher, hooks:[{type:command,…}]}` entry into
/// `hooks.<hooks_key>` of a JSON settings file. Always repairs in place: an
/// existing entry carrying [`MARKER`] (possibly with a stale binary path) is
/// dropped before the fresh one is added, so the array never accumulates
/// duplicates. Returns a human status line; never errors on a malformed
/// file (reports + leaves it untouched).
///
/// # Errors
/// Propagates directory-create / write I/O failure.
pub fn install_json_hook(
    path: &Path,
    hooks_key: &str,
    matcher: &str,
    command: &str,
) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut root: serde_json::Value = if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                return Ok(format!(
                    "! {} is not valid JSON - left unchanged; add the hook manually",
                    path.display()
                ));
            }
        }
    };
    let Some(root_obj) = root.as_object_mut() else {
        return Ok(format!(
            "! {} is not a JSON object - left unchanged",
            path.display()
        ));
    };
    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let Some(hooks_obj) = hooks.as_object_mut() else {
        return Ok(format!(
            "! {} `hooks` is not an object - left unchanged",
            path.display()
        ));
    };
    let arr = hooks_obj
        .entry(hooks_key)
        .or_insert_with(|| serde_json::json!([]));
    let Some(arr_vec) = arr.as_array_mut() else {
        return Ok(format!(
            "! {} hooks.{hooks_key} is not a list - left unchanged",
            path.display()
        ));
    };
    let present = arr_vec.iter().any(|e| e.to_string().contains(MARKER));
    arr_vec.retain(|e| !e.to_string().contains(MARKER));
    arr_vec.push(serde_json::json!({
        "matcher": matcher,
        "hooks": [{ "type": "command", "command": command }],
    }));
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(path, body + "\n")?;
    let verb = if present { "refreshed" } else { "wired" };
    Ok(format!("+ {verb} hook -> {}", path.display()))
}

/// Remove our entry from `hooks.<hooks_key>` of a JSON settings file,
/// pruning the array (and the `hooks` object) when they end up empty so an
/// uninstall leaves no husk behind. Unrelated entries and top-level keys
/// are preserved verbatim.
///
/// # Errors
/// Propagates write I/O failure.
pub fn uninstall_json_hook(path: &Path, hooks_key: &str) -> std::io::Result<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(format!("= nothing to remove: {}", path.display()));
    };
    let Ok(mut root) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(format!(
            "! {} is not valid JSON - left unchanged",
            path.display()
        ));
    };
    let mut removed = false;
    if let Some(arr) = root
        .get_mut("hooks")
        .and_then(|h| h.get_mut(hooks_key))
        .and_then(|a| a.as_array_mut())
    {
        let before = arr.len();
        arr.retain(|e| !e.to_string().contains(MARKER));
        removed = arr.len() != before;
    }
    if !removed {
        return Ok(format!("= no {MARKER} entry in {}", path.display()));
    }
    // Prune empty containers our removal created.
    if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut())
        && hooks
            .get(hooks_key)
            .and_then(|a| a.as_array())
            .is_some_and(Vec::is_empty)
    {
        hooks.remove(hooks_key);
    }
    if root
        .get("hooks")
        .and_then(|h| h.as_object())
        .is_some_and(serde_json::Map::is_empty)
    {
        root.as_object_mut().map(|o| o.remove("hooks"));
    }
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(path, body + "\n")?;
    Ok(format!("- removed hook <- {}", path.display()))
}

// ── Codex (TOML, sentinel-fenced) ────────────────────────────────────────────

/// Marker lines fencing the managed region of Codex's `config.toml`, so
/// install/uninstall can splice it in and out without a TOML parser.
const CODEX_SENTINEL_START: &str = "# >>> burn agent (managed) >>>";
const CODEX_SENTINEL_END: &str = "# <<< burn agent (managed) <<<";

/// Escape a value for a TOML basic string (`"..."`).
fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The managed `config.toml` region: separator, start sentinel, the
/// `PreToolUse` hook block, end sentinel.
fn codex_managed_block(command: &str) -> String {
    let cmd = toml_escape(command);
    let mut block = String::new();
    let _ = writeln!(block);
    let _ = writeln!(block, "{CODEX_SENTINEL_START}");
    let _ = write!(
        block,
        "[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"{cmd}\"\n"
    );
    let _ = writeln!(block, "{CODEX_SENTINEL_END}");
    block
}

/// Remove the inclusive sentinel region (and a single preceding blank
/// line) if present; otherwise return the text unchanged.
fn strip_codex_managed_region(text: &str) -> String {
    let (Some(s), Some(e)) = (
        text.find(CODEX_SENTINEL_START),
        text.find(CODEX_SENTINEL_END),
    ) else {
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

/// Write the `PreToolUse` hook block into `~/.codex/config.toml`, fenced by
/// managed sentinels. Splices a prior managed region out first (repairing a
/// stale binary path); a hook present *outside* the sentinels (hand-added)
/// is reported, never duplicated or deleted.
///
/// # Errors
/// Propagates I/O failure.
pub fn install_codex_hook(path: &Path, command: &str) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let present = existing.contains(MARKER);
    let base = strip_codex_managed_region(&existing);
    if present && base == existing {
        return Ok(format!(
            "! {} has a {MARKER} entry outside the managed block - remove it by hand first",
            path.display()
        ));
    }
    let body = format!(
        "{}{}",
        base.trim_end_matches('\n'),
        codex_managed_block(command)
    );
    std::fs::write(path, body)?;
    let verb = if present { "refreshed" } else { "wired" };
    Ok(format!("+ {verb} hook -> {}", path.display()))
}

/// Splice the managed region out of `~/.codex/config.toml`.
///
/// # Errors
/// Propagates write I/O failure.
pub fn uninstall_codex_hook(path: &Path) -> std::io::Result<String> {
    let Ok(existing) = std::fs::read_to_string(path) else {
        return Ok(format!("= nothing to remove: {}", path.display()));
    };
    let base = strip_codex_managed_region(&existing);
    if base == existing {
        return Ok(format!("= no {MARKER} entry in {}", path.display()));
    }
    std::fs::write(path, base)?;
    Ok(format!("- removed hook <- {}", path.display()))
}

// ── Cursor (hooks.json, bare command entries) ────────────────────────────────

/// Idempotently write the `beforeShellExecution` hook into
/// `~/.cursor/hooks.json`. Same repair-in-place semantics as
/// [`install_json_hook`]; preserves unrelated hooks and top-level keys.
///
/// # Errors
/// Propagates directory-create / write I/O failure.
pub fn install_cursor_hook(path: &Path, command: &str) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut root: serde_json::Value = if text.trim().is_empty() {
        serde_json::json!({ "version": 1 })
    } else {
        match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                return Ok(format!(
                    "! {} is not valid JSON - left unchanged; add the hook manually",
                    path.display()
                ));
            }
        }
    };
    let Some(root_obj) = root.as_object_mut() else {
        return Ok(format!(
            "! {} is not a JSON object - left unchanged",
            path.display()
        ));
    };
    let hooks = root_obj
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let Some(hooks_obj) = hooks.as_object_mut() else {
        return Ok(format!(
            "! {} `hooks` is not an object - left unchanged",
            path.display()
        ));
    };
    let arr = hooks_obj
        .entry("beforeShellExecution")
        .or_insert_with(|| serde_json::json!([]));
    let Some(arr_vec) = arr.as_array_mut() else {
        return Ok(format!(
            "! {} hooks.beforeShellExecution is not a list - left unchanged",
            path.display()
        ));
    };
    let present = arr_vec.iter().any(|e| e.to_string().contains(MARKER));
    arr_vec.retain(|e| !e.to_string().contains(MARKER));
    arr_vec.push(serde_json::json!({ "command": command }));
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(path, body + "\n")?;
    let verb = if present { "refreshed" } else { "wired" };
    Ok(format!("+ {verb} hook -> {}", path.display()))
}

// ── Copilot (dedicated hooks file) ───────────────────────────────────────────

/// Write `~/.copilot/hooks/burn.json` - a file we own entirely, so install
/// is a plain (over)write and uninstall deletes the file.
///
/// # Errors
/// Propagates directory-create / write I/O failure.
pub fn install_copilot_hook(path: &Path, command: &str) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let present = path.exists();
    let root = serde_json::json!({
        "version": 1,
        "hooks": { "preToolUse": [{ "type": "command", "command": command }] },
    });
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(path, body + "\n")?;
    let verb = if present { "refreshed" } else { "wired" };
    Ok(format!("+ {verb} hook -> {}", path.display()))
}

// ── Antigravity (named hook groups in hooks.json) ────────────────────────────

/// The top-level group key we own in agy's `hooks.json` - install writes
/// it whole, uninstall deletes it whole, nothing else is touched.
const AGY_GROUP: &str = "burn-agent";

/// Write the `burn-agent` group into `~/.gemini/config/hooks.json`:
/// `{"burn-agent":{"enabled":true,"PreToolUse":[{matcher,hooks:[…]}]}}`.
/// Same repair-in-place + leave-malformed-files-alone contract as the
/// other JSON hosts.
///
/// # Errors
/// Propagates directory-create / write I/O failure.
pub fn install_antigravity_hook(path: &Path, command: &str) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut root: serde_json::Value = if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                return Ok(format!(
                    "! {} is not valid JSON - left unchanged; add the hook manually",
                    path.display()
                ));
            }
        }
    };
    let Some(root_obj) = root.as_object_mut() else {
        return Ok(format!(
            "! {} is not a JSON object - left unchanged",
            path.display()
        ));
    };
    let present = root_obj.contains_key(AGY_GROUP);
    root_obj.insert(
        AGY_GROUP.to_string(),
        serde_json::json!({
            "enabled": true,
            "PreToolUse": [{
                "matcher": "run_command",
                "hooks": [{ "type": "command", "command": command }],
            }],
        }),
    );
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(
        path,
        body + "
",
    )?;
    let verb = if present { "refreshed" } else { "wired" };
    Ok(format!("+ {verb} hook -> {}", path.display()))
}

/// Delete the `burn-agent` group (the inverse of
/// [`install_antigravity_hook`]).
///
/// # Errors
/// Propagates write I/O failure.
pub fn uninstall_antigravity_hook(path: &Path) -> std::io::Result<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(format!("= nothing to remove: {}", path.display()));
    };
    let Ok(mut root) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(format!(
            "! {} is not valid JSON - left unchanged",
            path.display()
        ));
    };
    let removed = root
        .as_object_mut()
        .is_some_and(|o| o.remove(AGY_GROUP).is_some());
    if !removed {
        return Ok(format!("= no {AGY_GROUP} group in {}", path.display()));
    }
    let body = serde_json::to_string_pretty(&root).map_err(std::io::Error::other)?;
    std::fs::write(
        path,
        body + "
",
    )?;
    Ok(format!("- removed hook <- {}", path.display()))
}

// ── orchestration ────────────────────────────────────────────────────────────

/// Wire the pre-tool hook for `key`. `user=true` writes the home-dir config
/// (the default); `false` writes the project's where the host supports it.
/// Always repairs in place (replaces an entry baked with a stale path).
///
/// # Errors
/// Propagates I/O failure, or `InvalidInput` for an unknown host.
pub fn wire_host(key: &str, user: bool) -> std::io::Result<String> {
    let cmd = hook_command(key);
    let path = config_path(key, user);
    match key {
        "claude-code" => install_json_hook(&path, "PreToolUse", "Bash", &cmd),
        "gemini" => install_json_hook(&path, "BeforeTool", "run_shell_command", &cmd),
        "codex" => install_codex_hook(&path, &cmd),
        "cursor" => install_cursor_hook(&path, &cmd),
        "copilot" => install_copilot_hook(&path, &cmd),
        "antigravity" => install_antigravity_hook(&path, &cmd),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown host: {other}"),
        )),
    }
}

/// Remove the pre-tool hook for `key` (the inverse of [`wire_host`]).
///
/// # Errors
/// Propagates I/O failure, or `InvalidInput` for an unknown host.
pub fn unwire_host(key: &str, user: bool) -> std::io::Result<String> {
    let path = config_path(key, user);
    match key {
        "claude-code" => uninstall_json_hook(&path, "PreToolUse"),
        "gemini" => uninstall_json_hook(&path, "BeforeTool"),
        "codex" => uninstall_codex_hook(&path),
        "cursor" => uninstall_json_hook(&path, "beforeShellExecution"),
        "copilot" => {
            if path.exists() {
                std::fs::remove_file(&path)?;
                Ok(format!("- removed hook <- {}", path.display()))
            } else {
                Ok(format!("= nothing to remove: {}", path.display()))
            }
        }
        "antigravity" => uninstall_antigravity_hook(&path),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown host: {other}"),
        )),
    }
}

/// Hook status for one host, as shown by `burn agent status`.
pub struct HostStatus {
    /// The assistant looks installed (binary on PATH or config dir exists).
    pub detected: bool,
    /// Our hook entry is present in the host's config.
    pub wired: bool,
    /// The hook entry exists but bakes a binary path that is not the
    /// currently running `burn` (e.g. after a reinstall elsewhere).
    pub stale: bool,
}

/// Inspect a host's wiring without touching anything.
#[must_use]
pub fn status_host(key: &str, user: bool) -> HostStatus {
    let detected = spec(key).is_some_and(is_installed);
    let path = config_path(key, user);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let wired = text.contains(MARKER);
    let stale = wired && !text.contains(&hook_command(key));
    HostStatus {
        detected,
        wired,
        stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("burn-agent-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn json_hook_merges_idempotently_and_preserves_existing() {
        let dir = tmp("json");
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"theme":"dark"}"#).unwrap();

        let cmd = "/usr/local/bin/burn agent hook --host claude-code";
        let msg = install_json_hook(&path, "PreToolUse", "Bash", cmd).unwrap();
        assert!(msg.contains("wired"));
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark"); // unrelated settings preserved
        assert!(
            v["hooks"]["PreToolUse"].as_array().unwrap()[0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains(MARKER)
        );

        // Second install -> refresh in place, never a duplicate.
        assert!(
            install_json_hook(&path, "PreToolUse", "Bash", cmd)
                .unwrap()
                .contains("refreshed")
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_install_replaces_a_stale_path_without_duplicating() {
        let dir = tmp("jstale");
        let path = dir.join("settings.json");

        install_json_hook(
            &path,
            "PreToolUse",
            "Bash",
            "/old/burn agent hook --host claude-code",
        )
        .unwrap();
        install_json_hook(
            &path,
            "PreToolUse",
            "Bash",
            "/new/burn agent hook --host claude-code",
        )
        .unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "no duplicate entry");
        let cmd = arr[0]["hooks"][0]["command"].as_str().unwrap();
        assert!(cmd.contains("/new/"), "uses the current path");
        assert!(!cmd.contains("/old/"), "stale path dropped");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_uninstall_round_trip_restores_the_original_shape() {
        let dir = tmp("jround");
        let path = dir.join("settings.json");
        std::fs::write(&path, "{\n  \"theme\": \"dark\"\n}\n").unwrap();

        install_json_hook(
            &path,
            "PreToolUse",
            "Bash",
            "/x/burn agent hook --host claude-code",
        )
        .unwrap();
        let msg = uninstall_json_hook(&path, "PreToolUse").unwrap();
        assert!(msg.contains("removed"));

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert!(v.get("hooks").is_none(), "empty hooks containers pruned");

        // Second uninstall is a no-op, not an error.
        assert!(
            uninstall_json_hook(&path, "PreToolUse")
                .unwrap()
                .contains("no ")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_uninstall_preserves_unrelated_hooks() {
        let dir = tmp("jpres");
        let path = dir.join("settings.json");
        std::fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other-tool hook"}]}]}}"#,
        )
        .unwrap();

        install_json_hook(
            &path,
            "PreToolUse",
            "Bash",
            "/x/burn agent hook --host claude-code",
        )
        .unwrap();
        uninstall_json_hook(&path, "PreToolUse").unwrap();

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "the other tool's hook survives");
        assert!(arr[0].to_string().contains("other-tool"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_json_is_reported_and_left_unchanged() {
        let dir = tmp("jbad");
        let path = dir.join("settings.json");
        std::fs::write(&path, "{not json").unwrap();

        let msg = install_json_hook(&path, "PreToolUse", "Bash", "x burn agent hook").unwrap();
        assert!(msg.starts_with('!'));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");

        let msg = uninstall_json_hook(&path, "PreToolUse").unwrap();
        assert!(msg.starts_with('!'));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn codex_install_uninstall_round_trip_preserves_user_config() {
        let dir = tmp("codex");
        let path = dir.join("config.toml");
        std::fs::write(&path, "model = \"o3\"\n").unwrap();

        install_codex_hook(&path, "/x/burn agent hook --host codex").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("model = \"o3\""));
        assert!(text.contains("[[hooks.PreToolUse]]"));
        assert_eq!(text.matches(CODEX_SENTINEL_START).count(), 1);

        // Re-install with a new path -> splice + rewrite, no dupes.
        install_codex_hook(&path, "/new/burn agent hook --host codex").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(MARKER).count(), 1);
        assert!(text.contains("/new/"));
        assert!(!text.contains("/x/"));

        let msg = uninstall_codex_hook(&path).unwrap();
        assert!(msg.contains("removed"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("model = \"o3\""));
        assert!(!text.contains(MARKER));
        assert!(!text.contains(CODEX_SENTINEL_START));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cursor_install_and_uninstall_preserve_unrelated_hooks() {
        let dir = tmp("cursor");
        let path = dir.join("hooks.json");
        std::fs::write(
            &path,
            r#"{"version":1,"hooks":{"beforeShellExecution":[{"command":"echo hello"}]}}"#,
        )
        .unwrap();

        install_cursor_hook(&path, "/x/burn agent hook --host cursor").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "original hook + ours");

        uninstall_json_hook(&path, "beforeShellExecution").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0].to_string().contains("echo hello"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copilot_install_writes_and_uninstall_deletes_the_file() {
        let dir = tmp("copilot");
        let path = dir.join("hooks").join("burn.json");

        install_copilot_hook(&path, "/x/burn agent hook --host copilot").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["hooks"]["preToolUse"][0]["type"], "command");
        assert!(
            v["hooks"]["preToolUse"][0]["command"]
                .as_str()
                .unwrap()
                .contains(MARKER)
        );

        // Uninstall = delete the dedicated file.
        std::fs::remove_file(&path).unwrap();
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn antigravity_group_install_uninstall_round_trip() {
        let dir = tmp("agy");
        let path = dir.join("hooks.json");
        std::fs::write(&path, r#"{"user-group":{"enabled":true}}"#).unwrap();

        install_antigravity_hook(&path, "/x/burn agent hook --host antigravity").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["burn-agent"]["enabled"], true);
        assert_eq!(v["burn-agent"]["PreToolUse"][0]["matcher"], "run_command");
        assert!(
            v["burn-agent"]["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains(MARKER)
        );
        assert_eq!(v["user-group"]["enabled"], true, "other groups preserved");

        // Refresh in place: still one group.
        install_antigravity_hook(&path, "/new/burn agent hook --host antigravity").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            v["burn-agent"]["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("/new/")
        );

        let msg = uninstall_antigravity_hook(&path).unwrap();
        assert!(msg.contains("removed"));
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v.get("burn-agent").is_none());
        assert_eq!(v["user-group"]["enabled"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn toml_escape_handles_backslashes_and_quotes() {
        assert_eq!(toml_escape(r"C:\bin\burn"), r"C:\\bin\\burn");
        assert_eq!(toml_escape(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn unknown_host_errors() {
        assert!(wire_host("emacs", true).is_err());
        assert!(unwire_host("emacs", true).is_err());
    }
}
