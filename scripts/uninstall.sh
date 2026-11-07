#!/bin/sh
# Sealvra v0.1 uninstaller (Linux / macOS) -- W20.
#
# DEFAULT BEHAVIOUR: remove the PROGRAM only (zipapp + launcher).
# Vault data, platform-keychain items, and audit data are PRESERVED
# by default and are never deleted silently. Reinstalling afterwards
# picks the preserved data back up.
#
# --wipe-data is a separate, explicitly confirmed option:
#   * it is refused unless --confirm-wipe is ALSO passed, and
#   * it then asks the user to type WIPE before anything is deleted.
# Before any deletion, a pre-wipe audit record is written twice: once
# appended to the vault audit log (if one exists) and once to a
# wipe-receipt file OUTSIDE the vault directory, so evidence of the
# wipe survives the wipe itself.
#
# Wipe ordering (v3 section 1S, N-S6): live sessions are killed first
# where a launcher is still available; only then is data removed.
#
# WARNING, stated in the script and at wipe time: wiping the local
# vault does NOT revoke provider-side keys. A wiped key can still be
# used by anyone who already holds it. Revoking/rotating keys at the
# provider (GitHub / Gemini) is a separate user step and is NOT done
# by this script.
#
# Keychain honesty: platform-keychain items (macOS keychain, Secret
# Service, DPAPI) are owned by the vault module (W02 naming); this
# script does not guess their names and does not claim to delete them.
# On wipe it prints that keychain cleanup, if any items exist, is a
# manual step. Do not read this script as claiming a keychain wipe.
#
# Usage:
#   scripts/uninstall.sh [--prefix DIR] [--vault-dir DIR]
#   scripts/uninstall.sh --wipe-data --confirm-wipe [--prefix DIR]
#                        [--vault-dir DIR]
# Defaults: prefix = $HOME/.local,
# vault dir = ${SEALVRA_HOME:-$HOME/.sealvra}.

set -eu

PREFIX="$HOME/.local"
VAULT_DIR="${SEALVRA_HOME:-$HOME/.sealvra}"
WIPE=0
CONFIRM_WIPE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --vault-dir) VAULT_DIR="$2"; shift 2 ;;
        --vault-dir=*) VAULT_DIR="${1#--vault-dir=}"; shift ;;
        --wipe-data) WIPE=1; shift ;;
        --confirm-wipe) CONFIRM_WIPE=1; shift ;;
        --help|-h)
            echo "usage: uninstall.sh [--prefix DIR] [--vault-dir DIR]"
            echo "       uninstall.sh --wipe-data --confirm-wipe [--prefix DIR] [--vault-dir DIR]"
            exit 0 ;;
        *) echo "uninstall.sh: unexpected argument: $1" >&2; exit 1 ;;
    esac
done

if [ "$WIPE" -eq 1 ] && [ "$CONFIRM_WIPE" -ne 1 ]; then
    echo "uninstall.sh: --wipe-data was given without --confirm-wipe." >&2
    echo "uninstall.sh: refusing to delete any data. Nothing was removed." >&2
    exit 1
fi

PROGRAM_DIR="$PREFIX/share/sealvra"
LAUNCHER="$PREFIX/bin/sealvra"

# Kill live sessions first (best effort; a missing launcher or a
# stopped daemon is not an error here -- the program is being removed).
if [ -x "$LAUNCHER" ]; then
    "$LAUNCHER" sessions kill-all >/dev/null 2>&1 || true
fi

# Remove the program (always; this is the default action too).
rm -f "$LAUNCHER"
rm -rf "$PROGRAM_DIR"
echo "removed sealvra program and launcher."

if [ "$WIPE" -eq 0 ]; then
    echo "preserved (NOT deleted): vault data, platform-keychain items, and audit data."
    echo "vault directory left untouched: $VAULT_DIR"
    echo "to delete data as well, re-run with: uninstall.sh --wipe-data --confirm-wipe"
    exit 0
fi

# --- Wipe path: separately confirmed, pre-wipe audit record first. ---
printf 'This will DELETE the local vault and audit data at %s.\n' "$VAULT_DIR"
printf 'WARNING: wiping the local vault does NOT revoke provider-side keys.\n'
printf 'Revoking/rotating keys at GitHub / Gemini is a separate user step.\n'
printf 'Type WIPE to confirm, anything else to abort: '
read -r TYPED || TYPED=""
if [ "$TYPED" != "WIPE" ]; then
    echo "uninstall.sh: confirmation did not match WIPE; aborting. Nothing was deleted." >&2
    exit 1
fi

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RECORD="{\"event_type\": \"vault_wipe\", \"ts\": \"$TS\", \"vault_dir_removed\": true, \"note\": \"local wipe only; provider-side keys NOT revoked\"}"
RECEIPT="$HOME/sealvra-wipe-receipt-$TS.json"
# Pre-wipe record: append to the vault audit log first (if a vault
# exists), then to a receipt OUTSIDE the vault so it survives deletion.
if [ -d "$VAULT_DIR" ]; then
    printf '%s\n' "$RECORD" >> "$VAULT_DIR/audit.log" 2>/dev/null || true
fi
printf '%s\n' "$RECORD" > "$RECEIPT"
echo "pre-wipe audit record written to: $RECEIPT"

rm -rf "$VAULT_DIR"
echo "deleted vault directory: $VAULT_DIR"
echo "wipe receipt kept at: $RECEIPT"
echo "manual step (not done by this script): remove any platform-keychain"
echo "items for Sealvra, and rotate/revoke the keys at GitHub / Gemini,"
echo "because wiping local data does NOT revoke provider-side keys."
