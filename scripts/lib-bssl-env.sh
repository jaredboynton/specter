#!/usr/bin/env bash
# Resolve BORING_BSSL_PATH and BORING_BSSL_INCLUDE_PATH for a given Rust target
# triple. Source this script; it exports the two env vars if a prebuilt
# BoringSSL is found or can be installed from jaredboynton/bssl-prebuild.
#
# Usage:
#     . "$(dirname "$0")/lib-bssl-env.sh" "<rust-target-triple>"
#
# Resolution order:
#   1. BORING_BSSL_PATH already exported in the environment (e.g. from
#      ~/.zshrc) - used as-is, no rewrite.
#   2. ${BORING_BSSL_PREBUILT_ROOT:-$HOME/boringssl}/<target>/build/
#      Optional user-wide cache.
#   3. <repo>/lib/boringssl/<target>/build/
#      Ignored repo-local cache populated by install-boringssl-prebuilt.sh.
#   4. Auto-install into <repo>/lib/boringssl/ from npm packages such as
#      @jaredboynton/bssl-prebuild-<target>, unless BORING_BSSL_AUTO_INSTALL=0.
#
# Headers are looked for next to whichever path won, then under
# <root>/include as a last fallback.

set -u

_bssl_target="${1:-}"
if [[ -z "$_bssl_target" ]]; then
    echo "lib-bssl-env.sh: missing target argument" >&2
    return 1 2>/dev/null || exit 1
fi

# Use *.lib on Windows targets, *.a everywhere else.
case "$_bssl_target" in
    *-pc-windows-*) _bssl_libfile="ssl.lib" ;;
    *)              _bssl_libfile="libssl.a" ;;
esac

_bssl_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
_bssl_repo_root="$(cd "$_bssl_script_dir/.." && pwd)"

# Candidate roots in priority order.
_bssl_user_root="${BORING_BSSL_PREBUILT_ROOT:-$HOME/boringssl}"
_bssl_repo_path="$_bssl_repo_root/lib/boringssl/$_bssl_target/build"
_bssl_user_path="$_bssl_user_root/$_bssl_target/build"
_bssl_repo_include="$_bssl_repo_root/lib/boringssl/include"
_bssl_installer="$_bssl_repo_root/scripts/install-boringssl-prebuilt.sh"
_bssl_manifest="${BORING_BSSL_MANIFEST:-$_bssl_repo_root/Cargo.toml}"

_bssl_resolved_lib=""
_bssl_resolved_include=""

if [[ -n "${BORING_BSSL_PATH:-}" && -f "$BORING_BSSL_PATH/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$BORING_BSSL_PATH"
    _bssl_resolved_include="${BORING_BSSL_INCLUDE_PATH:-}"
elif [[ -f "$_bssl_user_path/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$_bssl_user_path"
    if   [[ -d "$_bssl_user_root/include" ]];                then _bssl_resolved_include="$_bssl_user_root/include"
    elif [[ -d "$_bssl_user_root/$_bssl_target/include" ]];  then _bssl_resolved_include="$_bssl_user_root/$_bssl_target/include"
    fi
elif [[ -f "$_bssl_repo_path/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$_bssl_repo_path"
    if   [[ -d "$_bssl_repo_include" ]];                                   then _bssl_resolved_include="$_bssl_repo_include"
    elif [[ -d "$_bssl_repo_root/lib/boringssl/$_bssl_target/include" ]];  then _bssl_resolved_include="$_bssl_repo_root/lib/boringssl/$_bssl_target/include"
    fi
fi

if [[ -z "$_bssl_resolved_lib" && "${BORING_BSSL_AUTO_INSTALL:-1}" != "0" && -x "$_bssl_installer" ]]; then
    echo "BoringSSL: installing external prebuilt for $_bssl_target" >&2
    if "$_bssl_installer" --manifest-path "$_bssl_manifest" "$_bssl_target" >&2; then
        if [[ -f "$_bssl_repo_path/$_bssl_libfile" ]]; then
            _bssl_resolved_lib="$_bssl_repo_path"
            if [[ -d "$_bssl_repo_include" ]]; then
                _bssl_resolved_include="$_bssl_repo_include"
            fi
        fi
    else
        echo "BoringSSL: external prebuilt install failed for $_bssl_target" >&2
    fi
fi

if [[ -n "$_bssl_resolved_lib" ]]; then
    export BORING_BSSL_PATH="$_bssl_resolved_lib"
    if [[ -n "$_bssl_resolved_include" ]]; then
        export BORING_BSSL_INCLUDE_PATH="$_bssl_resolved_include"
    fi
    echo "BoringSSL: using prebuilt at $BORING_BSSL_PATH" >&2
else
    echo "BoringSSL: no prebuilt for $_bssl_target at \$BORING_BSSL_PATH, $_bssl_user_path, or $_bssl_repo_path" >&2
    echo "           boring-sys will build from source via cmake (slower)" >&2
    echo "           To skip this: ./scripts/install-boringssl-prebuilt.sh --manifest-path Cargo.toml $_bssl_target" >&2
fi

unset _bssl_target _bssl_libfile _bssl_script_dir _bssl_repo_root
unset _bssl_user_root _bssl_repo_path _bssl_user_path _bssl_repo_include
unset _bssl_installer _bssl_manifest
unset _bssl_resolved_lib _bssl_resolved_include
