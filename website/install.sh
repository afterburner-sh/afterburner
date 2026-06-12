#!/bin/sh
# POSIX-sh installer for the `burn` CLI.
#
#   curl -fsSL https://afterburner.sh | sh
#
# (Served by the afterburner.sh Cloudflare Worker, which dispatches
# by user agent — curl/wget get this; PowerShell gets install.ps1.)
#
# Honors:
#   BURN_VERSION   pinned tag (e.g. v0.1.3). Defaults to "latest".
#   BURN_INSTALL   install dir. Defaults to $HOME/.local/bin (no sudo).
#
# Tested under bash, zsh, dash, ash (Alpine BusyBox), ksh, mksh.

set -eu

repo="afterburner-sh/afterburner"
install_dir="${BURN_INSTALL:-${HOME}/.local/bin}"

die() {
    printf 'burn install: %s\n' "$1" >&2
    exit 1
}

# ----- platform detection -----------------------------------------------

uname_s=$(uname -s 2>/dev/null || echo unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)

case "${uname_s}" in
    Linux*)             os="unknown-linux-gnu"; archive="tar.gz" ;;
    Darwin*)            os="apple-darwin";       archive="tar.gz" ;;
    MINGW*|MSYS*|CYGWIN*) os="pc-windows-msvc";  archive="zip"    ;;
    *) die "unsupported OS '${uname_s}'" ;;
esac

case "${uname_m}" in
    x86_64|amd64)   arch="x86_64"  ;;
    aarch64|arm64)  arch="aarch64" ;;
    *) die "unsupported architecture '${uname_m}'" ;;
esac

# Published-target fallbacks for (os, arch) combos the release
# matrix doesn't ship.
#
# Intel Mac (Darwin x86_64): not published — GitHub's macos-13
# runner is EOL. Rosetta 2 only goes Apple-Silicon→x86, not the
# reverse, so Intel Macs literally cannot run our aarch64 binary.
# Fail with a "build from source" pointer.
#
# ARM Windows (PROCESSOR_ARCHITECTURE=ARM64): not published — the
# rustls Ring crypto backend lacks aarch64-windows assembly.
# Windows 11 on ARM64 ships with transparent x64 emulation, so the
# x86_64 binary runs unmodified. Fall back to x86_64 with a note.
fallback_note=""
if [ "${os}" = "apple-darwin" ] && [ "${arch}" = "x86_64" ]; then
    die "Intel macOS is no longer in the release matrix (the GitHub macos-13 runner that builds it is end-of-life). Build from source: https://github.com/${repo}#building-from-source"
fi
if [ "${os}" = "pc-windows-msvc" ] && [ "${arch}" = "aarch64" ]; then
    arch="x86_64"
    fallback_note="ARM Windows: installing the x86_64 build (runs under Windows 11 x64 emulation)."
fi

target="${arch}-${os}"

# ----- pick a downloader -----------------------------------------------
#
# `fetch_archive` shows a progress bar (the binary is multi-MB, the
# user wants to see it move). `fetch_quiet` is silent for tiny
# fetches (tag JSON, .sha256). Both follow redirects + fail on HTTP
# error.
#
# When stdout is not a TTY (piped to `bash`, written to a log) the
# progress bar is suppressed, avoiding the `\r`-spam-into-logs
# problem.

if [ -t 1 ]; then progress_curl="--progress-bar"; progress_wget="--show-progress"; else progress_curl="-s"; progress_wget="-q"; fi

if command -v curl >/dev/null 2>&1; then
    fetch_archive() { curl -fL ${progress_curl} "$1" -o "$2"; }
    fetch_quiet()   { curl -fsSL "$1" -o "$2"; }
    fetch_stdout()  { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch_archive() { wget ${progress_wget} -O "$2" "$1"; }
    fetch_quiet()   { wget -q -O "$2" "$1"; }
    fetch_stdout()  { wget -q -O- "$1"; }
else
    die "neither 'curl' nor 'wget' is installed"
fi

# ----- version ----------------------------------------------------------

version="${BURN_VERSION:-latest}"
if [ "${version}" = "latest" ]; then
    api="https://api.github.com/repos/${repo}/releases/latest"
    # Parse `"tag_name": "vX.Y.Z"` without depending on jq. The
    # POSIX `sed` regex is intentionally simple — the field is well-
    # formed JSON from GitHub's API.
    tag=$(fetch_stdout "${api}" \
        | tr -d '\r' \
        | grep -m1 '"tag_name"' \
        | sed -e 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    [ -z "${tag}" ] && die "could not resolve latest release tag"
else
    tag="${version}"
fi

ver="${tag#v}"
stem="burn-${ver}-${target}"
asset="${stem}.${archive}"
url="https://github.com/${repo}/releases/download/${tag}/${asset}"

# ----- download + verify ------------------------------------------------

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t burnXXXXXX)
trap 'rm -rf "${tmp}"' EXIT INT TERM HUP

printf 'burn install: %s -> %s\n' "${tag}" "${target}"
[ -n "${fallback_note}" ] && printf '  note: %s\n' "${fallback_note}"
printf '  fetching %s\n' "${url}"

fetch_archive "${url}" "${tmp}/${asset}"
fetch_quiet "${url}.sha256" "${tmp}/${asset}.sha256" 2>/dev/null || true

# Verify checksum if we got one. Pick whichever sha256 tool the
# system ships — sha256sum (Linux), shasum -a 256 (macOS/BSD).
if [ -s "${tmp}/${asset}.sha256" ]; then
    expected=$(awk 'NF{print $1; exit}' "${tmp}/${asset}.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')
    else
        actual=""
    fi
    if [ -n "${actual}" ]; then
        if [ "${expected}" != "${actual}" ]; then
            die "SHA-256 mismatch (expected ${expected}, got ${actual})"
        fi
        printf '  sha256 ok\n'
    fi
fi

# ----- extract ----------------------------------------------------------

case "${archive}" in
    tar.gz)
        ( cd "${tmp}" && tar -xzf "${asset}" )
        bin_src="${tmp}/${stem}/burn"
        ;;
    zip)
        if command -v unzip >/dev/null 2>&1; then
            ( cd "${tmp}" && unzip -q "${asset}" )
        else
            die "'unzip' is required to extract ${asset}"
        fi
        bin_src="${tmp}/burn.exe"
        ;;
esac

[ -f "${bin_src}" ] || die "expected ${bin_src} after extraction"

# ----- install ---------------------------------------------------------

mkdir -p "${install_dir}"
case "${archive}" in
    zip) target_bin="${install_dir}/burn.exe" ;;
    *)   target_bin="${install_dir}/burn"     ;;
esac

cp "${bin_src}" "${target_bin}"
chmod +x "${target_bin}"

# ----- PATH update ------------------------------------------------------
#
# If the install dir isn't on PATH, append a single `export
# PATH=...` line to the user's primary shell rc (idempotent —
# checked by literal-string match before writing). Mirrors the UX
# bun, rustup, and deno ship: install scripts that "just work" and
# tell the user what they did, instead of leaving them with a
# binary that isn't on their PATH.
#
# Sets `BURN_INSTALL_NO_PATH=1` skips this for users who manage
# their own PATH (chezmoi, nix-home, dotfiles repos).

rc_file=""
rc_kind=""
rc_already_configured=""
if [ -z "${BURN_INSTALL_NO_PATH:-}" ]; then
    case ":${PATH}:" in
        *":${install_dir}:"*) ;;
        *)
            # Pick the rc by login shell. Fall back to .profile,
            # which is sourced by sh/bash/dash/ksh on login.
            shell_name="$(basename "${SHELL:-/bin/sh}")"
            case "${shell_name}" in
                zsh)
                    rc_file="${ZDOTDIR:-${HOME}}/.zshrc"; rc_kind="zsh"
                    ;;
                bash)
                    # macOS bash reads .bash_profile on login but
                    # not .bashrc; Linux bash reads .bashrc on
                    # interactive non-login. Prefer .bashrc when it
                    # exists (Linux default), else .bash_profile
                    # (macOS default), else create .bashrc.
                    if [ -f "${HOME}/.bashrc" ]; then
                        rc_file="${HOME}/.bashrc"
                    elif [ -f "${HOME}/.bash_profile" ]; then
                        rc_file="${HOME}/.bash_profile"
                    else
                        rc_file="${HOME}/.bashrc"
                    fi
                    rc_kind="bash"
                    ;;
                fish)
                    # Fish is its own thing — config.fish lives
                    # under XDG_CONFIG_HOME and the syntax is
                    # `set -gx PATH ...`, not POSIX `export`.
                    rc_file="${XDG_CONFIG_HOME:-${HOME}/.config}/fish/config.fish"
                    rc_kind="fish"
                    ;;
                *)
                    # ksh, dash, ash, mksh, busybox sh — all read
                    # ~/.profile on login.
                    rc_file="${HOME}/.profile"; rc_kind="posix"
                    ;;
            esac

            export_line=""
            case "${rc_kind}" in
                fish) export_line="set -gx PATH \"${install_dir}\" \$PATH" ;;
                *)    export_line="export PATH=\"${install_dir}:\$PATH\"" ;;
            esac

            # Idempotency: skip if the install dir is already
            # mentioned in the rc. Checks both literal-path and
            # `$HOME` variants so we don't double-write when the
            # user has already added it manually.
            home_relative_dir=$(printf '%s' "${install_dir}" | sed -e "s|^${HOME}|\$HOME|" -e "s|^${HOME}|~|")
            if [ -f "${rc_file}" ] && (grep -F -- "${install_dir}" "${rc_file}" >/dev/null 2>&1 \
                                        || grep -F -- "${home_relative_dir}" "${rc_file}" >/dev/null 2>&1); then
                # Re-run case: rc already mentions our install dir.
                # Don't write again; surface a "source it" message
                # below instead of the misleading "add to your rc".
                rc_already_configured="${rc_file}"
                rc_file=""
            else
                # Create the rc file's parent dir for fish (the
                # ~/.config/fish/ tree may not exist on a fresh
                # box). For everything else `~` is guaranteed.
                rc_parent=$(dirname "${rc_file}")
                mkdir -p "${rc_parent}" 2>/dev/null || true
                {
                    printf '\n# burn (https://afterburner.sh)\n'
                    printf '%s\n' "${export_line}"
                } >> "${rc_file}" || rc_file=""
            fi
            ;;
    esac
fi

# ----- summary ----------------------------------------------------------
#
# Mirrors bun/rustup tone: "X was installed successfully to PATH",
# blank line, what we did to PATH, blank line, "to get started, run".
# Every line is informational — no action required if the user is
# happy to `source` and go.

printf '\nburn was installed successfully to %s\n' "${target_bin}"
if [ -n "${rc_file}" ]; then
    # First run: we just edited rc_file with the export line.
    printf '\nAdded "%s" to $PATH in "%s"\n' "${install_dir}" "${rc_file}"
    printf '\nTo get started, run:\n\n'
    printf '  source %s\n' "${rc_file}"
    printf '  burn --version\n'
elif [ -n "${rc_already_configured}" ]; then
    # Re-run: rc already had us. Either the user already sourced
    # (PATH has it → just say "go") or they need to source/restart
    # (PATH lacks it → point at the rc they already configured).
    case ":${PATH}:" in
        *":${install_dir}:"*)
            printf '\nTo get started, run:\n\n  burn --version\n'
            ;;
        *)
            printf '\n%s is already configured in %s.\n' "${install_dir}" "${rc_already_configured}"
            printf 'Source it or open a new shell to use the new install:\n\n'
            printf '  source %s\n' "${rc_already_configured}"
            printf '  burn --version\n'
            ;;
    esac
else
    # BURN_INSTALL_NO_PATH=1 or rc-edit failed.
    case ":${PATH}:" in
        *":${install_dir}:"*)
            printf '\nTo get started, run:\n\n  burn --version\n'
            ;;
        *)
            printf '\nNote: %s is not on $PATH. Add it to your shell rc, or\n' "${install_dir}"
            printf '      run %s --version directly.\n' "${target_bin}"
            ;;
    esac
fi
