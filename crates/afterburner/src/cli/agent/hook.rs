// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The per-tool-call hook shim - what the assistant spawns before every
//! shell command. Reads the host's hook JSON from stdin, classifies the
//! command (see [`super::classify`]), and either prints nothing (allow -
//! defer to the host's normal permission flow) or the host's deny JSON
//! with the corrected `burn`-prefixed command as the reason.
//!
//! Design constraints:
//! * **Fail-open.** This is a convenience redirect, not a security gate:
//!   unparseable stdin, an unfamiliar payload shape, or a non-shell tool
//!   must never block the assistant. (Sandboxing is enforced by burn
//!   itself when the corrected command runs - not by this hook.)
//! * **Fast.** No engine init, no network, no file I/O - the hook runs on
//!   every tool call.
//! * **Escape hatch.** `BURN_AGENT_HOOK=0|off|false` disables the redirect
//!   without uninstalling.

use std::io::Read;
use std::path::PathBuf;

use super::classify::{Verdict, classify};

/// The persistent kill switch written by `burn agent disable` - one
/// `stat()` per hook invocation, nothing else.
pub fn disabled_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".config")
        });
    base.join("burn").join("agent.disabled")
}

/// A supported assistant host, selecting the deny-JSON dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    ClaudeCode,
    Codex,
    Gemini,
    Cursor,
    Copilot,
    Antigravity,
    /// Unknown host string: emit a generic `{decision, reason}` shape.
    Generic,
}

impl Host {
    /// Parse the `--host` value. Unknown names map to [`Host::Generic`]
    /// (fail-open: a future host still gets a usable JSON verdict).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "claude-code" | "claude" => Self::ClaudeCode,
            "codex" => Self::Codex,
            "gemini" => Self::Gemini,
            "cursor" => Self::Cursor,
            "copilot" => Self::Copilot,
            "antigravity" | "agy" => Self::Antigravity,
            _ => Self::Generic,
        }
    }
}

/// Tool names that mean "execute a shell command" across hosts. Anything
/// else (file edits, web fetches, MCP tools) is not ours to inspect.
fn is_shell_tool(name: &str) -> bool {
    matches!(
        name,
        "Bash"
            | "bash"
            | "shell"
            | "Shell"
            | "run_shell_command"
            | "run_command"
            | "run_terminal_cmd"
            | "terminal"
    )
}

/// Pull the shell command out of a hook payload, tolerating the field
/// layouts of every supported host:
/// * Claude Code / Codex / Copilot: `{"tool_name":"Bash","tool_input":{"command":…}}`
/// * Gemini CLI: same shape with `run_shell_command`
/// * Cursor (`beforeShellExecution`): `{"command":…}` at the top level
///
/// Returns `None` (allow) when the payload names a non-shell tool or has
/// no command string anywhere we recognise.
fn extract_command(v: &serde_json::Value) -> Option<String> {
    let tool = v
        .get("tool_name")
        .or_else(|| v.get("toolName"))
        .or_else(|| v.get("tool"))
        .and_then(|t| t.as_str());
    if let Some(t) = tool
        && !is_shell_tool(t)
    {
        return None; // a named non-shell tool is never inspected
    }
    for input_key in ["tool_input", "toolInput", "input", "arguments", "args"] {
        if let Some(cmd) = v
            .get(input_key)
            .and_then(|i| i.get("command"))
            .and_then(|c| c.as_str())
        {
            return Some(cmd.to_string());
        }
    }
    // Antigravity (agy): {"toolCall":{"name":…,"args":{"CommandLine":…}}}.
    if let Some(cmd) = v
        .get("toolCall")
        .and_then(|t| t.get("args"))
        .and_then(|a| a.get("CommandLine"))
        .and_then(|c| c.as_str())
    {
        return Some(cmd.to_string());
    }
    // Cursor's beforeShellExecution payload: top-level `command`.
    v.get("command")
        .and_then(|c| c.as_str())
        .map(ToString::to_string)
}

/// The deny response for a host. (Allow never emits anything.)
fn deny_json(host: Host, reason: &str) -> String {
    let body = match host {
        Host::ClaudeCode | Host::Codex => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }),
        // agy speaks the same {decision, reason} dialect as Gemini CLI.
        Host::Gemini | Host::Antigravity => {
            serde_json::json!({ "decision": "deny", "reason": reason })
        }
        Host::Cursor => serde_json::json!({
            "permission": "deny",
            "user_message": "Rerouting JavaScript into the burn sandbox",
            "agent_message": reason,
        }),
        Host::Copilot => serde_json::json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }),
        Host::Generic => serde_json::json!({ "decision": "deny", "reason": reason }),
    };
    body.to_string()
}

/// Whether the redirect is globally suppressed: the `BURN_AGENT_HOOK`
/// env escape hatch or the persistent `burn agent disable` flag file.
/// Read once per invocation; kept out of [`respond`] so the dialect logic
/// is testable without touching the developer's real `$HOME`.
fn redirect_suppressed() -> bool {
    matches!(
        std::env::var("BURN_AGENT_HOOK").as_deref(),
        Ok("0" | "off" | "false")
    ) || disabled_path().exists()
}

/// Process one hook payload. Returns the response to print, or `None` to
/// stay silent (allow). Pure: classify + dialect only, no global state -
/// the enable/disable gate is applied by the caller ([`run`]) so this
/// stays directly golden-testable.
#[must_use]
pub fn respond(host: Host, stdin: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdin).ok()?; // fail-open
    let command = extract_command(&v)?;
    match classify(&command) {
        Verdict::Allow => None,
        Verdict::Redirect { reason, .. } => Some(deny_json(host, &reason)),
    }
}

/// `burn agent hook --host <h>`: the assistant-facing entry point.
///
/// # Errors
/// Never - all failure modes are fail-open (silent allow, exit 0).
pub fn run(host: &str) -> anyhow::Result<()> {
    let mut stdin = String::new();
    // A read error is fail-open: allow silently.
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        return Ok(());
    }
    // The global gate (env / disable flag) lives here, not in respond().
    if redirect_suppressed() {
        return Ok(());
    }
    if let Some(out) = respond(Host::parse(host), &stdin) {
        println!("{out}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude_payload(command: &str) -> String {
        serde_json::json!({
            "session_id": "s1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string()
    }

    #[test]
    fn node_command_is_denied_with_the_corrected_command() {
        let out = respond(Host::ClaudeCode, &claude_payload("node app.js")).expect("deny");
        assert!(out.contains("\"permissionDecision\":\"deny\""));
        assert!(out.contains("burn --sandbox node app.js"));
        assert!(out.contains("PreToolUse"));
    }

    #[test]
    fn safe_commands_stay_silent() {
        assert!(respond(Host::ClaudeCode, &claude_payload("npm install express")).is_none());
        assert!(respond(Host::ClaudeCode, &claude_payload("git status")).is_none());
        assert!(respond(Host::ClaudeCode, &claude_payload("burn node app.js")).is_none());
    }

    #[test]
    fn non_shell_tools_are_never_inspected() {
        let payload = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "command": "node app.js", "file_path": "x" },
        })
        .to_string();
        assert!(respond(Host::ClaudeCode, &payload).is_none());
    }

    #[test]
    fn garbage_stdin_is_fail_open() {
        assert!(respond(Host::ClaudeCode, "not json at all").is_none());
        assert!(respond(Host::ClaudeCode, "").is_none());
        assert!(respond(Host::ClaudeCode, "{}").is_none());
    }

    #[test]
    fn gemini_dialect_uses_decision_field() {
        let payload = serde_json::json!({
            "tool_name": "run_shell_command",
            "tool_input": { "command": "npx tsx main.ts" },
        })
        .to_string();
        let out = respond(Host::Gemini, &payload).expect("deny");
        assert!(out.contains("\"decision\":\"deny\""));
        assert!(out.contains("burn --sandbox npx tsx main.ts"));
    }

    #[test]
    fn cursor_top_level_command_shape_is_understood() {
        let payload = serde_json::json!({ "command": "node -e 'console.log(1)'" }).to_string();
        let out = respond(Host::Cursor, &payload).expect("deny");
        assert!(out.contains("\"permission\":\"deny\""));
        assert!(out.contains("agent_message"));
    }

    #[test]
    fn antigravity_tool_call_shape_is_understood() {
        let payload = serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "node app.js" } },
        })
        .to_string();
        let out = respond(Host::Antigravity, &payload).expect("deny");
        assert!(out.contains("\"decision\":\"deny\""));
        assert!(out.contains("burn --sandbox node app.js"));
        let safe = serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "git status" } },
        })
        .to_string();
        assert!(respond(Host::Antigravity, &safe).is_none());
    }

    #[test]
    fn copilot_dialect_is_flat() {
        let payload = serde_json::json!({
            "tool_name": "bash",
            "tool_input": { "command": "npm test" },
        })
        .to_string();
        let out = respond(Host::Copilot, &payload).expect("deny");
        assert!(out.contains("\"permissionDecision\":\"deny\""));
        assert!(!out.contains("hookSpecificOutput"));
    }
}
