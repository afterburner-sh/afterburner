#!/bin/sh
# POSIX-sh uninstaller for the `burn` CLI — the exact inverse of
# install.sh:
#
#   curl -fsSL https://afterburner.sh/uninstall | sh
#
# Undoes everything install.sh did, and nothing else:
#   1. Removes the installed binary (burn / burn.exe) from the
#      install dir, and the dir itself if that leaves it empty.
#   2. Removes the PATH block install.sh appended to the shell rc
#      (the `# burn (https://afterburner.sh)` marker line plus its
#      export/set line). All rc candidates are scrubbed — the login
#      shell may have changed since install. PATH lines the user
#      added by hand (no marker) are left alone.
#
# State created by *running* burn (registry logins, caches) is not
# install.sh's doing and is deliberately untouched.
#
# Honors:
#   BURN_INSTALL   install dir. Defaults to $HOME/.local/bin —
#                  must match what was used at install time.
#
# Tested under bash, zsh, dash, ash (Alpine BusyBox), ksh, mksh.

set -eu

install_dir="${BURN_INSTALL:-${HOME}/.local/bin}"
marker='# burn (https://afterburner.sh)'

die() {
    printf 'burn uninstall: %s\n' "$1" >&2
    exit 1
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t burnXXXXXX)
trap 'rm -rf "${tmp}"' EXIT INT TERM HUP

# ----- 1. binary ---------------------------------------------------------

removed_bin=""
for name in burn burn.exe; do
    if [ -f "${install_dir}/${name}" ]; then
        rm -f "${install_dir}/${name}"
        removed_bin="${install_dir}/${name}"
        printf 'burn uninstall: removed %s\n' "${removed_bin}"
    fi
done
[ -z "${removed_bin}" ] \
    && printf 'burn uninstall: no binary at %s (already removed?)\n' "${install_dir}"

# install.sh `mkdir -p`s the install dir; remove it again if (and
# only if) it is now empty — rmdir refuses otherwise.
rmdir "${install_dir}" 2>/dev/null && printf 'burn uninstall: removed empty %s\n' "${install_dir}" || true

# ----- 2. shell rc PATH block -------------------------------------------
#
# Remove the exact block install.sh wrote:
#
#     <blank line>
#     # burn (https://afterburner.sh)
#     export PATH="<install_dir>:$PATH"     (or fish `set -gx PATH ...`)
#
# The marker comment is the key: only marker-tagged lines are
# touched, so a PATH entry the user wrote themselves survives.

scrub_rc() {
    rc="$1"
    [ -f "${rc}" ] || return 0
    grep -F -- "${marker}" "${rc}" >/dev/null 2>&1 || return 0

    awk -v marker="${marker}" -v dir="${install_dir}" '
        {
            if ($0 == marker) { drop = 1; held = 0; next }
            if (drop) { drop = 0; if (index($0, dir) > 0) next }
            if ($0 == "") { if (held) print ""; held = 1; next }
            if (held) { print ""; held = 0 }
            print
        }
        END { if (held) print "" }
    ' "${rc}" > "${tmp}/rc.scrubbed" || return 0

    # cat-over (not mv) keeps the rc file inode, permissions, and any
    # symlink (dotfile managers) intact.
    cat "${tmp}/rc.scrubbed" > "${rc}"
    printf 'burn uninstall: removed PATH block from %s\n' "${rc}"
}

scrub_rc "${ZDOTDIR:-${HOME}}/.zshrc"
scrub_rc "${HOME}/.bashrc"
scrub_rc "${HOME}/.bash_profile"
scrub_rc "${XDG_CONFIG_HOME:-${HOME}/.config}/fish/config.fish"
scrub_rc "${HOME}/.profile"

# ----- summary -----------------------------------------------------------

printf '\nburn was uninstalled.\n'
printf 'Open a new shell (or re-source your rc) for $PATH to update.\n'
