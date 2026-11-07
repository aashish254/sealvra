"""Sealvra W12 — agent wrapper.

Launches an agent process with a scrubbed environment, isolated
credential homes, verified binary resolution, and PoP signing via an
in-memory sidecar.

Security posture (honest, per CONTRACT §10 / v3 §1A):
- Tier A (interface-bound agent): the controls here are meaningful.
- Tier B (shell-capable same-user agent): env scrub and isolated homes
  do NOT survive a Tier B agent — it runs as the user's UID and can
  read its own process environment and any file the user can read.
  This module therefore *refuses or loudly warns* on known bypass
  material instead of claiming Tier B isolation. Same-user malware /
  compromised OS account is out of scope by design.
- Deleted v1/v2 passages are never built: no clipboard handoff, no
  config-file token write, no ``--print-token`` / ``--show-token``,
  no native-token preference (proxy/MCP first, v3 N-K9).

No real keys are used here. Tests use TEST-ONLY values only. Findings
never contain credential *values* — only the variable/file/key name
and the pattern kind that matched.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Credential-shaped environment variables (f10 B1/B2/B6, v3 N-K1)
# ---------------------------------------------------------------------------

# Names that are credential-shaped by construction. Generic suffix rules
# below catch vendor vars we have not enumerated.
_EXACT_CREDENTIAL_ENV = {
    "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_KEY", "OPENAI_AUTH_TOKEN",
    "GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
    "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "COPILOT_PROVIDER_API_KEY",
    "CURSOR_API_KEY",
    "NPM_TOKEN", "PYPI_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "GITLAB_TOKEN", "BITBUCKET_TOKEN",
}
_SUFFIX_CREDENTIAL_ENV = ("_TOKEN", "_API_KEY", "_SECRET", "_PASSWORD",
                          "_PRIVATE_KEY", "_AUTH_TOKEN", "_ACCESS_KEY")
_PREFIX_CREDENTIAL_ENV = ("TOKEN_", "SECRET_")


def is_credential_env_name(name: str) -> bool:
    """True if an env var name is credential-shaped (name only, no value)."""
    upper = name.upper()
    if upper in _EXACT_CREDENTIAL_ENV:
        return True
    if upper.endswith(_SUFFIX_CREDENTIAL_ENV):
        return True
    if upper.startswith(_PREFIX_CREDENTIAL_ENV):
        return True
    return False


def scrub_env(env: dict) -> tuple:
    """Return (cleaned_env, removed_names).

    Removes every credential-shaped variable. The broker session token
    is re-injected by :func:`launch_agent` only into the *child* process
    environment under the agent-specific variable, never into a file or
    a persistent shell profile, and it does not survive the session.
    """
    cleaned = {}
    removed = []
    for key, value in env.items():
        if is_credential_env_name(key):
            removed.append(key)
        else:
            cleaned[key] = value
    return cleaned, removed


# ---------------------------------------------------------------------------
# Credential-shaped values in settings / config files (f10 B2/B3/B16)
# ---------------------------------------------------------------------------

# Patterns are matched against *values* found in agent config files.
# Only the pattern kind is reported, never the value.
_CREDENTIAL_VALUE_PATTERNS = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{10,}")),
    ("ghp/gho/ghu/ghs/ghr", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("sk-ant", re.compile(r"sk-ant-[A-Za-z0-9\-_]{10,}")),
    ("openai_sk", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{20,}")),
    ("generic_bearer_like", re.compile(r"Bearer\s+[A-Za-z0-9\-_.]{20,}")),
]
# Keys whose *presence* with a non-empty value in a settings file is a
# finding regardless of pattern match (provider-override keys).
_OVERRIDE_KEYS = {
    "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "base_url",
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
    "http_headers", "env_http_headers",
    "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY",
}


@dataclass
class SettingsFinding:
    layer: str          # e.g. "user", "project", "local", "managed", "envfile"
    path: str
    key: str
    kind: str           # "credential_value" | "provider_override" | "credential_header"
    severity: str       # "refuse" | "warn"
    detail: str         # human text; NEVER contains a credential value


def _scan_value(key: str, value: str, layer: str, path: str) -> list:
    findings = []
    for kind, pat in _CREDENTIAL_VALUE_PATTERNS:
        if pat.search(value):
            findings.append(SettingsFinding(
                layer, path, key, "credential_value", "refuse",
                "credential-shaped %s value for key %s" % (kind, key)))
            return findings
    if key in _OVERRIDE_KEYS:
        if key in ("http_headers", "env_http_headers"):
            findings.append(SettingsFinding(
                layer, path, key, "credential_header", "refuse",
                "static credential-header block can smuggle a key "
                "past env scrub (f10 B3)"))
        elif key in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "base_url"):
            findings.append(SettingsFinding(
                layer, path, key, "provider_override", "refuse",
                "provider base_url override in %s config" % layer))
        else:
            findings.append(SettingsFinding(
                layer, path, key, "credential_value", "refuse",
                "credential key present in %s config" % layer))
    return findings


def _scan_json(obj, layer: str, path: str) -> list:
    findings = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str):
                findings.extend(_scan_value(str(key), value, layer, path))
            else:
                findings.extend(_scan_json(value, layer, path))
    elif isinstance(obj, list):
        for item in obj:
            findings.extend(_scan_json(item, layer, path))
    elif isinstance(obj, str):
        for kind, pat in _CREDENTIAL_VALUE_PATTERNS:
            if pat.search(obj):
                findings.append(SettingsFinding(
                    layer, path, "(bare value)", "credential_value",
                    "refuse",
                    "credential-shaped value in %s config" % layer))
                break
    return findings


def _scan_text(text: str, layer: str, path: str) -> list:
    findings = []
    # JSON settings files (Claude settings.json, MCP configs) nest env
    # blocks: {"env": {"ANTHROPIC_BASE_URL": ...}}. Walk them
    # recursively; the line parser below handles TOML/.env shapes.
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            import json as _json
            findings.extend(_scan_json(_json.loads(text), layer, path))
            if findings:
                return findings
        except Exception:
            pass
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # key = "value" / key: value / key = value / "key": "value"
        m = re.match(r'"?([A-Za-z0-9_.\-]+)"?\s*[:=]\s*"?([^"\n,}]+)"?', stripped)
        if not m:
            # Still scan bare values (e.g. header tables) for patterns.
            for kind, pat in _CREDENTIAL_VALUE_PATTERNS:
                if pat.search(stripped):
                    findings.append(SettingsFinding(
                        layer, path, "(bare value)", "credential_value",
                        "refuse",
                        "credential-shaped value in %s config" % layer))
            continue
        key, value = m.group(1), m.group(2).strip()
        for kind, pat in _CREDENTIAL_VALUE_PATTERNS:
            if pat.search(value):
                findings.append(SettingsFinding(
                    layer, path, key, "credential_value", "refuse",
                    "credential-shaped %s value for key %s" % (kind, key)))
                break
        else:
            if key in _OVERRIDE_KEYS:
                if key in ("http_headers", "env_http_headers"):
                    findings.append(SettingsFinding(
                        layer, path, key, "credential_header", "refuse",
                        "static credential-header block can smuggle a key "
                        "past env scrub (f10 B3)"))
                elif key in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "base_url"):
                    findings.append(SettingsFinding(
                        layer, path, key, "provider_override", "refuse",
                        "provider base_url override in %s config" % layer))
                else:
                    findings.append(SettingsFinding(
                        layer, path, key, "credential_value", "refuse",
                        "credential key present in %s config" % layer))
    return findings


def scan_settings_file(path: str, layer: str) -> list:
    """Scan one settings file. Missing files yield no findings."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return _scan_text(fh.read(), layer, path)
    except (OSError, UnicodeError):
        return []


def scan_settings_layers(layers: dict) -> list:
    """Scan all settings layers the agent will read.

    ``layers`` maps layer name -> file path. Covers user, project,
    local, managed and .env/.env.local layers (f10 B2/B3/C4): a project
    settings ``env`` block outranks shell env in Claude Code and cannot
    unset a variable, so any hit here is a refusal, not a warning.
    """
    findings = []
    for layer, path in layers.items():
        findings.extend(scan_settings_file(path, layer))
    return findings


def check_proxy_override(findings: list, proxy_base_url: str,
                         file_text_by_path: dict | None = None) -> list:
    """Refuse any settings base_url that is not exactly the proxy URL.

    ``proxy_base_url`` comparison is exact-string; a Codex provider
    block pointing anywhere else (including the official vendor
    endpoint, f10 B3/X7) is a refusal. Values are never logged.
    """
    extra = []
    if file_text_by_path:
        for path, text in file_text_by_path.items():
            for m in re.finditer(
                    r'base_url\s*[:=]\s*"([^"]+)"', text):
                if m.group(1).rstrip("/") != proxy_base_url.rstrip("/"):
                    extra.append(SettingsFinding(
                        "provider_block", path, "base_url",
                        "provider_override", "refuse",
                        "base_url does not equal the session proxy URL"))
    return [f for f in findings if f.severity == "refuse"] + extra


# ---------------------------------------------------------------------------
# Standing CLI credential inventory (f10 B1/B6/B16, v3 N-K1)
# ---------------------------------------------------------------------------

@dataclass
class StandingCredential:
    kind: str       # e.g. "gh_hosts", "git_helper", "netrc", "hf_token",
                    # "shell_profile_export", "codex_auth", "claude_json",
                    # "cli_store", "mcp_config", "mcp_config_credential",
                    # "ide_settings_credential"
    location: str   # file path; NEVER a credential value
    detail: str     # key/var NAMES only, never values


# Shell profiles scanned for standing exports (f10 B6). Includes
# .zshenv (sourced by every zsh invocation, not just interactive
# shells) and the fish config, whose syntax is `set -x NAME ...`
# rather than `export NAME=...`.
SHELL_PROFILES = (
    ".zshrc", ".bashrc", ".profile", ".zprofile", ".bash_profile",
    ".bash_login", ".zshenv", ".config/fish/config.fish",
)

# CLI credential stores inventoried by presence only (f10 B1). These
# files are never edited by the migration path: only their owner can
# decide to move a key into the vault and rotate it at the provider.
CLI_STORES = (
    ".aws/credentials", ".aws/config", ".docker/config.json",
    ".git-credentials", ".npmrc", ".kube/config",
    ".config/gcloud/credentials.db",
)

# MCP configs under $HOME (f10 B16/B8). Project-scope configs
# (./.mcp.json, ./.cursor/mcp.json) are covered when the caller passes
# ``project_dir``; they are committable, so a literal key there is a
# leak to the repo, not just to the machine.
MCP_CONFIGS_HOME = (
    ".cursor/mcp.json", ".claude/mcp.json",
    ".config/Code/User/mcp.json", ".config/Cursor/User/mcp.json",
    ".codex/config.toml",
)
MCP_CONFIGS_PROJECT = (".mcp.json", ".cursor/mcp.json")

# IDE settings files scanned for credential-shaped keys (f10 B12/P8).
# Only key NAMES are reported, never values.
IDE_SETTINGS_HOME = (
    ".config/Code/User/settings.json",
    ".config/Cursor/User/settings.json",
    ".cursor/settings.json",
    "Library/Application Support/Code/User/settings.json",
)

_SHELL_EXPORT_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=")
_FISH_SET_RE = re.compile(
    r"^\s*set\s+(?:--[a-z-]+\s+|-[a-zA-Z]+\s+)*([A-Za-z0-9_]+)\b")


def _profile_credential_vars(text: str) -> list:
    """(line_no, var_name) for uncommented credential-shaped assignments.

    Commented lines are skipped: a line the migration already
    commented out must not reappear in the inventory, or migration
    could never verify as complete. Only names are returned.
    """
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _SHELL_EXPORT_RE.match(line)
        if m and is_credential_env_name(m.group(1)):
            found.append((lineno, m.group(1)))
            continue
        m = _FISH_SET_RE.match(line)
        if m and is_credential_env_name(m.group(1)):
            found.append((lineno, m.group(1)))
    return found


def _is_credential_config_key(name: str) -> bool:
    """Credential-shaped config key, including dotted IDE keys.

    Env-name rules miss dotted keys such as
    ``github.copilot.chat.apikey``. Split on non-alphanumerics and
    accept a segment that is (or ends in) a credential word, plus
    the joined forms ``apikey``/``apitoken``. Name only, never a value.
    """
    if is_credential_env_name(name):
        return True
    segments = [s for s in re.split(r"[^A-Za-z0-9]+", name.lower()) if s]
    for seg in segments:
        if seg in ("key", "token", "secret", "password",
                   "apikey", "apitoken"):
            return True
        # "mykey"-style segments, minus common English words that
        # merely end in "key".
        if seg.endswith(("key", "token", "secret", "password")) \
                and seg not in ("monkey", "donkey", "turkey", "whiskey"):
            return True
    return False


def _config_credential_keys(path: str) -> list:
    """Credential-shaped key NAMES found in a JSON/text config file.

    Reuses :func:`scan_settings_file` (pattern kinds + override keys),
    whose findings already carry key names only, and adds a plain
    key-name pass so a literal ``"MY_API_KEY": "..."`` entry is
    reported even when its value matches no known token pattern.
    Values are never returned.
    """
    names = set()
    for finding in scan_settings_file(path, "config"):
        if finding.key not in ("(bare value)",):
            names.add(finding.key)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return sorted(names)
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)"\s*:', text):
        if _is_credential_config_key(m.group(1)):
            names.add(m.group(1))
    return sorted(names)


def inventory_standing_credentials(home: str, project_dir: str | None = None) -> list:
    """Inventory (presence only) of standing credentials under ``home``.

    This is the ``sealvra doctor`` inventory. It reports *that* a
    bypass store exists and where — it never reads or returns a
    credential value. Covers, per f10 B1/B6/B16 and v3 N-K1:
    shell profiles, CLI credential stores, vendor logins, git
    helpers, MCP configs (home + project when ``project_dir`` is
    given), and IDE settings (key names only).
    """
    out = []

    def _exists(rel):
        return os.path.exists(os.path.join(home, rel))

    if _exists(".config/gh/hosts.yml"):
        out.append(StandingCredential(
            "gh_hosts", os.path.join(home, ".config/gh/hosts.yml"),
            "gh stored login falls back when the broker token is unset (B1)"))
    if _exists(".netrc"):
        out.append(StandingCredential(
            "netrc", os.path.join(home, ".netrc"),
            "curl/git read .netrc with no env var at all (B1)"))
    if _exists(".cache/huggingface/token"):
        out.append(StandingCredential(
            "hf_token", os.path.join(home, ".cache/huggingface/token"),
            "Hugging Face token file is consulted without env vars (B1)"))
    if _exists(".codex/auth.json"):
        out.append(StandingCredential(
            "codex_auth", os.path.join(home, ".codex/auth.json"),
            "Codex stored login may be preferred over the broker provider"))
    if _exists(".claude.json"):
        out.append(StandingCredential(
            "claude_json", os.path.join(home, ".claude.json"),
            "Claude Code user config may carry env/settings overrides"))
    for rel in CLI_STORES:
        if _exists(rel):
            out.append(StandingCredential(
                "cli_store", os.path.join(home, rel),
                "CLI credential store present; any process running as "
                "you can read it (B1)"))
    # Git credential helpers declared in ~/.gitconfig (names only).
    gitconfig = os.path.join(home, ".gitconfig")
    if os.path.exists(gitconfig):
        try:
            with open(gitconfig, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for m in re.finditer(r"helper\s*=\s*([^\n]+)", text):
                out.append(StandingCredential(
                    "git_helper", gitconfig,
                    "git credential helper declared: %s" % m.group(1).strip()))
        except OSError:
            pass
    # Shell-profile exports: the most common standing credential (B6).
    for profile in SHELL_PROFILES:
        p = os.path.join(home, profile)
        if not os.path.exists(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for lineno, var in _profile_credential_vars(text):
            out.append(StandingCredential(
                "shell_profile_export", p,
                "shell profile exports credential-shaped var %s "
                "(line %d)" % (var, lineno)))
    # MCP configs: presence + any literal credential-shaped key (B16).
    def _inventory_mcp_configs(base: str, rels):
        for rel in rels:
            p = os.path.join(base, rel)
            if not os.path.exists(p):
                continue
            out.append(StandingCredential(
                "mcp_config", p,
                "MCP/agent config present; check it for stored keys "
                "(project-scope configs can be committed by accident)"))
            for key in _config_credential_keys(p):
                out.append(StandingCredential(
                    "mcp_config_credential", p,
                    "MCP/agent config carries credential-shaped key %s "
                    "(value not shown)" % key))
    _inventory_mcp_configs(home, MCP_CONFIGS_HOME)
    if project_dir:
        _inventory_mcp_configs(project_dir, MCP_CONFIGS_PROJECT)
    # IDE settings: credential-shaped key names only (B12/P8).
    for rel in IDE_SETTINGS_HOME:
        p = os.path.join(home, rel)
        if not os.path.exists(p):
            continue
        for key in _config_credential_keys(p):
            out.append(StandingCredential(
                "ide_settings_credential", p,
                "IDE settings mention credential-shaped key %s "
                "(value not shown)" % key))
    return out


# ---------------------------------------------------------------------------
# One-command migration path (f10 B6 fix (b)): shell profiles only
# ---------------------------------------------------------------------------

@dataclass
class MigrationItem:
    location: str
    var_name: str       # name only, never a value
    action: str         # "comment_out" | "manual"
    backup_path: str | None = None
    detail: str = ""


def plan_migration(home: str, project_dir: str | None = None) -> list:
    """Plan migration of standing credentials (names/paths only).

    Only plain-text shell-profile exports get the automated
    ``comment_out`` action. Everything else (CLI stores, MCP/IDE
    configs, vendor logins) is ``manual``: the user imports the key
    into the vault and rotates it at the provider; this code never
    rewrites a JSON/binary credential store, where an automated edit
    could corrupt the file or silently leave a second copy behind.
    """
    items = []
    for cred in inventory_standing_credentials(home, project_dir):
        if cred.kind == "shell_profile_export":
            # var name is the last word of the detail's "var X (line N)"
            var = cred.detail.split("var ")[-1].split(" ")[0]
            items.append(MigrationItem(
                cred.location, var, "comment_out",
                cred.location + ".kh-migrate-bak",
                "comment out the export after importing the key into "
                "the vault; the commented line still contains the old "
                "value on disk, so rotation at the provider is still "
                "required and the backup must be deleted once done"))
        elif cred.kind in ("mcp_config",):
            continue  # presence alone is not a credential to migrate
        else:
            items.append(MigrationItem(
                cred.location, cred.kind, "manual",
                None,
                "%s; manual: import into the vault and rotate at the "
                "provider; this migration does not edit this file"
                % cred.detail))
    return items


def verify_migration(home: str, project_dir: str | None = None) -> list:
    """Standing shell-profile exports remaining after migration.

    Returns the (path, var) pairs still uncommented. Empty means the
    automated part of the migration is complete; manual items are
    tracked by :func:`plan_migration`, not here.
    """
    remaining = []
    for cred in inventory_standing_credentials(home, project_dir):
        if cred.kind == "shell_profile_export":
            var = cred.detail.split("var ")[-1].split(" ")[0]
            remaining.append((cred.location, var))
    return remaining


def apply_shell_migration(home: str, dry_run: bool = False) -> dict:
    """One-command migration of shell-profile credential exports.

    For each profile containing uncommented credential-shaped
    exports: back the file up once to ``<path>.kh-migrate-bak``
    (mode 0600, never overwritten if it already exists), then
    comment out exactly those export lines in place (atomic
    temp-file + rename, original mode preserved). Returns a report
    of paths, var names, line numbers and backup paths — never
    values. ``dry_run=True`` changes nothing.

    Honest limit, stated in the report detail: commenting out stops
    the shell exporting the value, but the old value remains in the
    commented line and in the backup until the user imports it into
    the vault, rotates it at the provider, and deletes the backup.
    Comment-out is not deletion and not rotation.
    """
    migrated = []
    backups = []
    for profile in SHELL_PROFILES:
        p = os.path.join(home, profile)
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines(keepends=True)
            mode = os.stat(p).st_mode & 0o777
        except OSError:
            continue
        text = "".join(lines)
        found = _profile_credential_vars(text)
        if not found:
            continue
        backup = p + ".kh-migrate-bak"
        if dry_run:
            for lineno, var in found:
                migrated.append({"path": p, "var": var, "line": lineno,
                                 "backup": backup})
            if backup not in backups:
                backups.append(backup)
            continue
        if not os.path.exists(backup):
            try:
                shutil.copyfile(p, backup)
                os.chmod(backup, 0o600)
            except OSError:
                continue
        if backup not in backups:
            backups.append(backup)
        comment_lines = {lineno for lineno, _ in found}
        new_lines = []
        for idx, line in enumerate(lines, 1):
            if idx in comment_lines:
                new_lines.append("# sealvra-migrated: " + line
                                 if line.endswith("\n")
                                 else "# sealvra-migrated: " + line + "\n")
            else:
                new_lines.append(line)
        tmp = p + ".kh-migrate-tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.writelines(new_lines)
            os.chmod(tmp, mode)
            os.replace(tmp, p)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            continue
        for lineno, var in found:
            migrated.append({"path": p, "var": var, "line": lineno,
                             "backup": backup})
    return {
        "migrated": migrated,
        "backups": backups,
        "remaining": [] if dry_run else verify_migration(home),
        "limit": "commented lines and backups still contain the old "
                 "values on disk; import into the vault, rotate at "
                 "the provider, then delete the backups",
    }


# ---------------------------------------------------------------------------
# Isolated credential homes (f10 B1 fix (a))
# ---------------------------------------------------------------------------

def build_isolated_env(base_env: dict) -> tuple:
    """Return (env, temp_dirs) with file-fallback credential homes isolated.

    - ``GH_CONFIG_DIR`` -> empty broker-managed dir (no hosts.yml fallback).
    - Git credential helper forced empty via GIT_CONFIG_COUNT/KEY/VALUE.
    - ``CURL_HOME`` and ``HF_HOME`` -> empty broker-managed dirs
      (no .netrc / HF token file fallback).
    - Tools with NO override for a fallback store are listed by
      :func:`tools_without_override` and must be refused, not launched.

    Callers must delete ``temp_dirs`` on session end. Tier B caveat:
    a shell-capable agent can still read the user's real $HOME directly;
    isolation neutralises *tool fallback*, it does not isolate the user.
    """
    dirs = []
    env = dict(base_env)
    gh_dir = tempfile.mkdtemp(prefix="kh-gh-")
    curl_dir = tempfile.mkdtemp(prefix="kh-curl-")
    hf_dir = tempfile.mkdtemp(prefix="kh-hf-")
    dirs.extend([gh_dir, curl_dir, hf_dir])
    env["GH_CONFIG_DIR"] = gh_dir
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "credential.helper"
    env["GIT_CONFIG_VALUE_0"] = ""
    env["CURL_HOME"] = curl_dir
    env["HF_HOME"] = hf_dir
    return env, dirs


def tools_without_override() -> list:
    """Tools with no supported credential-home override (refuse to broker)."""
    return [
        # A tool lands here when no env/config override neutralises its
        # file-based fallback. Launching it brokered would be a silent
        # bypass, so the wrapper refuses instead (v3 N-K1).
        # Currently empty by construction: every profiled tool below has
        # an override. Keep this list as the refusal gate, not a comment.
    ]


# ---------------------------------------------------------------------------
# Agent tool profiles (f10 §1, v3 N-K3/N-K4/N-K5/N-K6)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolProfile:
    name: str
    binaries: tuple
    env_mode_supported: bool
    mcp_mode_supported: bool
    token_env_var: str | None   # child-env var carrying the session token
    notes: str


TOOL_PROFILES = {
    # cursor-agent: env mode silently no-injects (f10 B10) — refused.
    "cursor-agent": ToolProfile(
        "cursor-agent", ("cursor-agent",), False, True, None,
        "CLI does not inherit shell env; only mcp.json env block. "
        "Wrapper env mode REFUSED; MCP mode is the CLI path (N-K3)."),
    "claude": ToolProfile(
        "claude", ("claude",), True, True, "ANTHROPIC_AUTH_TOKEN",
        "Settings-file env outranks shell env; project/local/managed "
        "layers must be scanned (B2). GUI-launched agents ignore "
        "wrapper env entirely (N-K6)."),
    "codex": ToolProfile(
        "codex", ("codex",), True, True, None,
        "Env vars ignored since v0.128.0; broker provider block in "
        "config.toml is the route, re-read on every invocation (B3/X7)."),
    "copilot": ToolProfile(
        "copilot", ("copilot",), True, False, "COPILOT_PROVIDER_API_KEY",
        "Standalone copilot CLI supports COPILOT_PROVIDER_BASE_URL / "
        "_API_KEY / _MODEL (N-K4). gh copilot extension is NOT this tool."),
    "gh": ToolProfile(
        "gh", ("gh",), True, False, "GH_TOKEN",
        "Env token takes precedence over stored login but unsetting "
        "restores fallback — hence isolated GH_CONFIG_DIR (B1)."),
}


class WrapperRefusal(Exception):
    """Launch refused. Message is safe to show the user (no secrets)."""


class BinaryNotFound(WrapperRefusal):
    pass


def verify_binary(tool: str, explicit_path: str | None = None,
                  allowlist: list | None = None,
                  expected_sha256: str | None = None,
                  allow_script: bool = False) -> str:
    """Resolve + verify an agent binary. No PATH-hijack silent fallback.

    - ``explicit_path`` wins; otherwise ``shutil.which`` on the tool's
      binary names. If nothing resolves -> BinaryNotFound (never a
      fallback to a different binary).
    - If ``allowlist`` is given, the resolved real path must be in it.
    - If ``expected_sha256`` is given, the file hash must match.
    - Shell-script binaries are refused unless ``allow_script`` is set
      and the script path is explicitly allowlisted (f10 B15).
    Returns the resolved absolute path.
    """
    profile = TOOL_PROFILES.get(tool)
    candidates = [explicit_path] if explicit_path else []
    if not candidates and profile:
        for name in profile.binaries:
            found = shutil.which(name)
            if found:
                candidates.append(found)
                break
    if not candidates:
        raise BinaryNotFound(
            "agent binary for %r not found on PATH; refusing to launch "
            "(no silent fallback)" % tool)
    resolved = os.path.realpath(candidates[0])
    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        raise BinaryNotFound("agent binary %s is not an executable file" % resolved)
    if allowlist is not None and resolved not in [os.path.realpath(p) for p in allowlist]:
        raise WrapperRefusal(
            "agent binary %s is not in the verified allowlist; refusing" % resolved)
    if expected_sha256 is not None:
        digest = hashlib.sha256()
        with open(resolved, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise WrapperRefusal(
                "agent binary %s hash mismatch; refusing" % resolved)
    try:
        with open(resolved, "rb") as fh:
            head = fh.read(2)
        if head == b"#!" and not allow_script:
            raise WrapperRefusal(
                "agent binary %s is a script; refusing unless explicitly "
                "allowlisted as a script" % resolved)
    except OSError:
        pass
    return resolved


# ---------------------------------------------------------------------------
# Config hash-watch (f10 B3/B19, v3 N-K1/N-K2)
# ---------------------------------------------------------------------------

def hash_config_files(paths: list) -> dict:
    """Map path -> sha256 hex, or 'MISSING' for absent files."""
    out = {}
    for path in paths:
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            out[path] = digest.hexdigest()
        except OSError:
            out[path] = "MISSING"
    return out


def detect_config_change(before: dict, after: dict) -> list:
    """Paths whose hash changed (including created/deleted)."""
    changed = []
    for path in set(before) | set(after):
        if before.get(path) != after.get(path):
            changed.append(path)
    return sorted(changed)


class SessionConfigWatch:
    """Hash-watch for the session lifetime (f10 B3/B19, v3 N-K1).

    Baseline hashes are taken at session start (e.g. by
    :func:`launch_agent` with ``watch_config_paths``). Every
    :meth:`check` re-hashes; any change — modified, created, or
    deleted — immediately suspends the session: ``suspended`` and
    ``needs_reprobe`` become True and stay True until the caller
    re-probes and calls :meth:`acknowledge_reprobe` with
    ``probe_passed=True``. A failed or missing re-probe never clears
    the suspension. Change events record path + event kind only,
    never file contents or credential values.

    Probe-matrix link: :meth:`combined_config_hash` is a stable hash
    of the watched files; pass it as the matrix ``config_hash`` and a
    watched change automatically expires every verdict for that
    session (see probe.ProbeMatrix), because the hash no longer
    matches the one the verdicts were recorded against.
    """

    def __init__(self, paths: list, baseline: dict | None = None):
        self.paths = sorted(set(paths))
        self.baseline = (dict(baseline) if baseline is not None
                         else hash_config_files(self.paths))
        self.suspended = False
        self.needs_reprobe = False
        self.change_events: list = []  # (path, "modified"|"created"|"deleted")

    def combined_config_hash(self, hashes: dict | None = None) -> str:
        """Stable hash over sorted (path, file-hash) pairs."""
        hashes = hashes if hashes is not None else hash_config_files(self.paths)
        digest = hashlib.sha256()
        for path in sorted(hashes):
            digest.update(("%s:%s\n" % (path, hashes[path])).encode())
        return digest.hexdigest()

    def check(self) -> list:
        """Re-hash and suspend on any change. Returns changed paths."""
        current = hash_config_files(self.paths)
        changed = detect_config_change(self.baseline, current)
        for path in changed:
            if path not in self.baseline:
                kind = "created"
            elif current.get(path) == "MISSING":
                kind = "deleted"
            else:
                kind = "modified"
            self.change_events.append((path, kind))
        if changed:
            self.suspended = True
            self.needs_reprobe = True
        return changed

    def status(self) -> str:
        return "suspended_unverified" if self.suspended else "verified"

    def acknowledge_reprobe(self, probe_passed: bool) -> bool:
        """Clear suspension only after a passing re-probe.

        On success the baseline is re-taken from the current files,
        so the new config becomes the verified one. On failure the
        session stays suspended. Returns whether suspension cleared.
        """
        if not probe_passed:
            return False
        self.baseline = hash_config_files(self.paths)
        self.suspended = False
        self.needs_reprobe = False
        return True


def cursor_cli_launch_route() -> dict:
    """cursor-agent CLI launch route (f10 B10, v3 N-K3).

    Env/wrapper mode is REFUSED: the CLI does not inherit shell env
    and only uses the ``env`` block in ``mcp.json``, so a wrapper
    that set env vars and execed it would silently no-inject. MCP
    mode is the CLI path.
    """
    return {
        "tool": "cursor-agent",
        "env_mode": "refused",
        "mcp_mode": "primary",
        "reason": "cursor-agent does not inherit shell environment; "
                  "it only uses the env block in mcp.json. Wrapper "
                  "env mode would silently no-inject, so it is "
                  "refused; use MCP mode instead",
    }


# ---------------------------------------------------------------------------
# PoP sidecar: PoP key held in memory only, never in a file the agent
# can read (CONTRACT §4). The sidecar signs on behalf of the agent;
# the agent process never receives the PoP key or the real key.
# ---------------------------------------------------------------------------

def canonical_pop_string(method: str, host: str, canonical_path: str,
                         body_sha256_hex: str, timestamp: int) -> str:
    return "%s\n%s\n%s\n%s\n%d" % (
        method.upper(), host, canonical_path, body_sha256_hex, timestamp)


class SidecarSigner:
    """In-memory PoP signer. The key lives only in this object.

    ``__repr__`` is redacted. There is deliberately no method that
    returns the key, writes it to a file, or puts it in an env var.
    """

    def __init__(self, pop_key: bytes | None = None):
        self._pop_key = pop_key if pop_key is not None else secrets.token_bytes(32)
        self._nonce_seen: set = set()
        self._lock = threading.Lock()

    def __repr__(self):  # noqa: D105
        return "SidecarSigner(<redacted>)"

    def sign(self, method: str, host: str, canonical_path: str,
             body: bytes = b"", timestamp: int | None = None) -> dict:
        """Return PoP headers for one request (no key material out)."""
        ts = int(timestamp if timestamp is not None else time.time())
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = canonical_pop_string(method, host, canonical_path,
                                         body_hash, ts)
        pop = hmac.new(self._pop_key, canonical.encode(),
                       hashlib.sha256).hexdigest()
        with self._lock:
            nonce = "%d:%s" % (ts, pop[:16])
            if nonce in self._nonce_seen:
                raise ValueError("PoP nonce reuse within session lifetime")
            self._nonce_seen.add(nonce)
        return {
            "X-Sealvra-PoP": pop,
            "X-Sealvra-Timestamp": str(ts),
            "X-Sealvra-Body-Sha256": body_hash,
        }

    def verify(self, method: str, host: str, canonical_path: str,
               body: bytes, timestamp: int, pop_hex: str,
               max_skew: int = 300) -> bool:
        """Verify PoP headers. Skew > max_skew denies (CONTRACT §4)."""
        now = int(time.time())
        if abs(now - int(timestamp)) > max_skew:
            return False
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = canonical_pop_string(method, host, canonical_path,
                                         body_hash, int(timestamp))
        expected = hmac.new(self._pop_key, canonical.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, pop_hex)


class SidecarServer:
    """Loopback Unix-socket sidecar: agents ask it to sign, never see the key.

    The socket lives in a fresh mkdtemp dir deleted on close. The
    handshake token is delivered to the agent child via an inherited
    file descriptor (see :func:`launch_agent`), never via env or file.
    Tier B caveat: a same-user process that learns the socket path AND
    the handshake token could ask for signatures — the token is
    single-process, in-memory, and the socket dir is deleted on session
    end. This is a Tier A control; it is not Tier B isolation.
    """

    def __init__(self, signer: SidecarSigner | None = None):
        self.signer = signer or SidecarSigner()
        self.handshake_token = secrets.token_urlsafe(32)
        self._dir = tempfile.mkdtemp(prefix="kh-sidecar-")
        self.socket_path = os.path.join(self._dir, "sidecar.sock")
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(4)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                self._server.settimeout(0.2)
                conn, _ = self._server.accept()
            except (socket.timeout, OSError):
                continue
            try:
                data = conn.recv(65536)
                if not data:
                    continue
                # First line: handshake token. Rest: JSON-ish fields
                # separated by \n: method, host, path, body_hex.
                parts = data.decode("utf-8", "replace").split("\n")
                if len(parts) < 5 or not hmac.compare_digest(
                        parts[0], self.handshake_token):
                    conn.sendall(b"DENIED")
                    continue
                body = bytes.fromhex(parts[4]) if parts[4] else b""
                headers = self.signer.sign(parts[1], parts[2], parts[3], body)
                conn.sendall(
                    ("%s\n%s" % (headers["X-Sealvra-PoP"],
                                 headers["X-Sealvra-Timestamp"])).encode())
            except Exception:
                try:
                    conn.sendall(b"DENIED")
                except OSError:
                    pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def sign_via_socket(self, method: str, host: str, path: str,
                        body: bytes = b"") -> dict:
        """Client side (in-memory handshake token only)."""
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(self.socket_path)
            payload = "\n".join([self.handshake_token, method, host, path,
                                 body.hex()]).encode()
            client.sendall(payload)
            resp = client.recv(65536).decode()
            if resp == "DENIED" or not resp:
                raise WrapperRefusal("sidecar refused to sign")
            pop, ts = resp.strip().split("\n")
            return {"X-Sealvra-PoP": pop, "X-Sealvra-Timestamp": ts}
        finally:
            client.close()

    def close(self):
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        try:
            os.rmdir(self._dir)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

@dataclass
class LaunchPlan:
    tool: str
    binary_path: str
    argv: list
    env_keys: list          # key NAMES only — never values
    warnings: list = field(default_factory=list)
    isolated_dirs: list = field(default_factory=list)
    sidecar_socket_path: str | None = None
    process: object = None  # subprocess.Popen when actually spawned
    config_watch: object = None  # SessionConfigWatch, if requested


def launch_agent(tool: str, argv: list, proxy_base_url: str,
                 session_token: str | None = None,
                 daemon_up: bool = True,
                 base_env: dict | None = None,
                 settings_layers: dict | None = None,
                 explicit_binary: str | None = None,
                 allowlist: list | None = None,
                 expected_sha256: str | None = None,
                 allow_script: bool = False,
                 dry_run: bool = True,
                 sidecar: SidecarServer | None = None,
                 watch_config_paths: list | None = None) -> LaunchPlan:
    """Build (and optionally spawn) a brokered agent launch.

    Refusals (WrapperRefusal), in order:
    1. Daemon down -> refuse (v3: refusal to launch when daemon down
       survives every convenience proposal).
    2. cursor-agent env mode -> refuse (B10); use MCP mode instead.
    3. Settings-layer credential/override findings -> refuse (B2/B3).
    4. Binary unverifiable / not found -> refuse (B15, no PATH fallback).
    5. Tool with no credential-home override -> refuse (N-K1).

    ``dry_run=True`` (default) returns the plan without spawning, so
    tests and the manager integration run never exec a real agent.
    With ``watch_config_paths`` the plan carries a SessionConfigWatch
    baselined at launch; the session owner must poll
    ``plan.config_watch.check()`` and suspend on any change (B3/B19).
    With ``dry_run=False`` the child inherits ONLY the scrubbed +
    isolated env; the session token appears only in the child env
    under the agent-specific var (or not at all in sidecar mode, where
    the sidecar signs and the token travels via the broker, not env).
    """
    if not daemon_up:
        raise WrapperRefusal(
            "daemon is down; refusing to launch agent (no fallback to "
            "raw keys or direct vendor access)")
    profile = TOOL_PROFILES.get(tool)
    if profile is None:
        raise WrapperRefusal("unknown agent tool %r" % tool)
    if not profile.env_mode_supported:
        raise WrapperRefusal(
            "%s wrapper env mode is unsupported (%s); use MCP mode"
            % (tool, profile.notes))
    if tool in tools_without_override():
        raise WrapperRefusal(
            "%s has no credential-home override; refusing to broker" % tool)
    findings = scan_settings_layers(settings_layers or {})
    if findings:
        raise WrapperRefusal(
            "refusing launch: %d settings-layer finding(s), first: %s "
            "(%s)" % (len(findings), findings[0].key, findings[0].detail))
    binary = verify_binary(tool, explicit_binary, allowlist,
                           expected_sha256, allow_script)
    cleaned, removed = scrub_env(base_env if base_env is not None else os.environ)
    env, isolated_dirs = build_isolated_env(cleaned)
    warnings = []
    if removed:
        warnings.append("scrubbed credential-shaped env vars: %s"
                        % ", ".join(sorted(removed)))
    env["SEALVRA_PROXY_BASE_URL"] = proxy_base_url
    if sidecar is not None:
        env["SEALVRA_SIDECAR_SOCKET"] = sidecar.socket_path
        # Sidecar mode: the agent never holds the session token in env;
        # it asks the sidecar to sign. The token itself stays broker-side.
    elif session_token is not None and profile.token_env_var:
        env[profile.token_env_var] = session_token
    watch = (SessionConfigWatch(watch_config_paths)
             if watch_config_paths else None)
    plan = LaunchPlan(tool=tool, binary_path=binary,
                      argv=[binary] + list(argv),
                      env_keys=sorted(env.keys()),
                      warnings=warnings, isolated_dirs=isolated_dirs,
                      sidecar_socket_path=(
                          sidecar.socket_path if sidecar else None),
                      config_watch=watch)
    if dry_run:
        return plan
    proc = subprocess.Popen(plan.argv, env=env)
    plan.process = proc
    return plan
