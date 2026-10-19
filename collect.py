#!/usr/bin/env python3
"""Tier 0 system health scan collector (M04, D-034, D-037, D-038).

Runs only the fixed Tier 0 read-only, offline, unprivileged command list,
normalizes output into allowlisted finding records with MAC/UUID/hostname
scrubbing, and writes one snapshot JSON file outside the repository via
atomic temporary-file write + rename without overwriting existing files.

Exit-code evidence (Task 3 specification, revision 2):
- `/usr/bin/pacdiff` (pacman-contrib 1.13.1, lines 318-373): in `-o` (`--output`)
  mode, iterates over pacmandb backup entries, echoes existing `.pacnew`,
  `.pacorig`, and `.pacsave[.N]` paths, and always ends with `exit 0` whether
  zero or more files were printed; exits `1` only on invalid flags or missing
  `/etc/pacman.conf` / `/var/lib/pacman/local`.
- `pacman(8)`, `paclog(1)`, and `systemctl(1)` man pages do not document a
  distinct exit status for "empty query result" versus errors on `-Qu`, `-Qm`,
  `-Qdt`, `-Qkk`, or `--failed`. Per revision 2 of the specification ("The
  Technician treats any non-zero exit as `failed` (`exit-status`) unless the
  man page or source documents the meaning"), any non-zero exit status is
  treated as `failed` (`reason: "exit-status"`), except on `integrity`
  (`pacman -Qkk`) when stderr/stdout reports `Permission denied`, which is
  recorded as `partial` (`reason: "permission"`) per the command table.
- Exceptions added by Claude Code (co-author, D-039), observed on this machine
  on 2026-10-19 with output discarded: `pacman -Qu` exits 1 and prints nothing
  when no update is pending, a normal healthy state. `pacman -Qm` and
  `pacman -Qdt` share pacman's query path and are assumed (unverified) to do
  the same. For these three checks, exit 1 with empty stdout and stderr is a
  valid empty result. `pacman -Qkk` is assumed (unverified until the first
  owner run) to exit 1 when it reports mismatches, so exit 1 counts as
  complete only when mismatch lines were parsed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
MAX_OUTPUT_BYTES = 16 * 1024 * 1024  # 16 MiB cap per check

# Fixed Tier 0 command table (AC2). Order and argv tuples are immutable.
COMMAND_TABLE: tuple[tuple[str, tuple[str, ...], int], ...] = (
    ("integrity", ("pacman", "-Qkk"), 300),
    ("paclog", ("paclog", "--logfile", "/var/log/pacman.log"), 60),
    ("updates", ("pacman", "-Qu"), 60),
    ("foreign", ("pacman", "-Qm"), 60),
    ("orphans", ("pacman", "-Qdt"), 60),
    ("pacdiff", ("pacdiff", "-o"), 60),
    ("failed-units", ("systemctl", "--system", "--failed", "--no-legend", "--no-pager", "--plain"), 60),
)

CHECK_IDS: tuple[str, ...] = tuple(cid for cid, _, _ in COMMAND_TABLE)

CHECK_STATUSES = frozenset({"ok", "partial", "failed"})
CHECK_REASONS = frozenset({
    "none",
    "missing-tool",
    "timeout",
    "exit-status",
    "parse",
    "permission",
    "truncated",
    "log-gap",
})

INTEGRITY_PROPERTIES = frozenset({
    "missing",
    "permissions",
    "ownership",
    "size",
    "mtime",
    "type",
    "other",
})

FINDING_SCHEMA: dict[str, tuple[str, str, frozenset[str]]] = {
    "integrity": ("file-property", "mismatch", frozenset()),
    "updates": ("local-update", "available", frozenset({"installed_version", "available_version"})),
    "foreign": ("foreign-package", "present", frozenset({"installed_version"})),
    "orphans": ("orphan-package", "present", frozenset({"installed_version"})),
    "pacdiff": ("pending-config", "present", frozenset()),
    "failed-units": ("failed-unit", "failed", frozenset({"load", "active", "sub"})),
    "paclog": ("log-warning", "observed", frozenset()),
}

MINIMAL_ENV: dict[str, str] = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
    "NO_COLOR": "1",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
    "PAGER": "cat",
}

UUID_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])"
)
MAC_COLON_RE = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])"
)
MAC_HYPHEN_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])"
)

INTEGRITY_SUMMARY_RE = re.compile(
    r"^[A-Za-z0-9@._+:-]+:\s+\d+\s+total files?,\s+\d+\s+altered files?\.?$"
)
INTEGRITY_NO_MTREE_RE = re.compile(
    r"^(?:warning:\s+)?[A-Za-z0-9@._+:-]+:\s+no mtree file$"
)
INTEGRITY_WARNING_RE = re.compile(
    r"^(?:warning:\s+)?([A-Za-z0-9@._+:-]+):\s+(/\S*)\s+\(([^()]+)\)$"
)
UPDATES_RE = re.compile(r"^([A-Za-z0-9@._+:-]+)\s+(\S+)\s+->\s+(\S+)(?:\s+\[ignored\])?$")
PKG_VERSION_RE = re.compile(r"^([A-Za-z0-9@._+:-]+)\s+(\S+)$")
PACDIFF_RE = re.compile(r"^(/\S+\.(?:pacnew|pacorig|pacsave(?:\.\d+)?))$")
FAILED_UNIT_RE = re.compile(
    r"^([A-Za-z0-9_.@:\\-]+\.(?:service|socket|timer|mount|automount|swap|target|path|slice|scope|device))\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+.*)?$"
)
PACLOG_LINE_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z))\]\s+\[([^\]]+)\]\s+(.*)$"
)
PACLOG_WARNING_PREFIXES = ("warning:", "error:", "note:")

# Checks where exit 1 with no output at all means "no results" (see module docstring).
EMPTY_RESULT_EXIT_ONE = frozenset({"updates", "foreign", "orphans"})


@dataclass(frozen=True)
class CommandResult:
    """Raw outcome of one Tier 0 command execution."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = 0
    missing_tool: bool = False
    timed_out: bool = False
    truncated: bool = False


def repo_root() -> Path:
    """Return the repository root containing `projects/health-scan/`."""
    return Path(__file__).resolve().parents[2]


def check_out_dir(out_dir: str | Path, root: Path | None = None) -> Path:
    """Resolve `out_dir` and refuse any path inside the repository (AC3)."""
    base = (root or repo_root()).resolve()
    raw_path = Path(out_dir).expanduser()
    # Check both lexical/parent resolution and symlink resolution so neither can
    # target a path inside the repository.
    resolved = raw_path.resolve()
    if resolved == base or base in resolved.parents:
        raise ValueError(f"--out directory {resolved} resolves inside repository {base}")
    abs_path = Path(os.path.abspath(str(raw_path)))
    if abs_path == base or base in abs_path.parents:
        raise ValueError(f"--out directory {abs_path} is inside repository {base}")
    return resolved


def scrub_text(value: str, hostname: str | None = None, *, scrub_host: bool = True) -> str:
    """Replace UUIDs with `<uuid>`, MAC addresses with `<mac>`, and hostname with `<host>` (AC4).

    `scrub_host=False` is for package names and versions, which come from the
    package database and cannot contain the hostname but can collide with it
    (hostname `archlinux` vs package `archlinux-keyring`; D-039).
    """
    if not isinstance(value, str):
        raise TypeError("scrub_text requires a str")
    out = UUID_RE.sub("<uuid>", value)
    out = MAC_COLON_RE.sub("<mac>", out)
    out = MAC_HYPHEN_RE.sub("<mac>", out)
    if not scrub_host:
        return out
    host = hostname if hostname is not None else socket.gethostname()
    candidates = []
    if host:
        candidates.append(host.strip())
        short = host.strip().split(".", 1)[0]
        if short and short != host.strip():
            candidates.append(short)
    for token in sorted(set(candidates), key=len, reverse=True):
        if token:
            out = re.sub(re.escape(token), "<host>", out, flags=re.IGNORECASE)
    return out


def _is_empty_result(check_id: str, res: CommandResult) -> bool:
    return (check_id in EMPTY_RESULT_EXIT_ONE and res.exit_code == 1
            and not (res.stdout or "").strip() and not (res.stderr or "").strip())


def _read_capped(proc: subprocess.Popen[bytes], timeout_s: int, cap_bytes: int) -> CommandResult:
    """Communicate with a child process with timeout and a hard byte cap."""
    try:
        out_b, err_b = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return CommandResult(exit_code=None, timed_out=True)

    if len(out_b) + len(err_b) > cap_bytes:
        return CommandResult(
            stdout=out_b[:cap_bytes].decode("utf-8", errors="replace"),
            stderr="",
            exit_code=proc.returncode,
            truncated=True,
        )
    return CommandResult(
        stdout=out_b.decode("utf-8", errors="replace"),
        stderr=err_b.decode("utf-8", errors="replace"),
        exit_code=proc.returncode,
    )


def run_tier0_command(check_id: str, argv: tuple[str, ...], timeout_s: int) -> CommandResult:
    """Execute one approved Tier 0 command with no shell, closed stdin, and minimal env."""
    expected = dict((cid, (cmd, tmo)) for cid, cmd, tmo in COMMAND_TABLE)
    if check_id not in expected or expected[check_id] != (argv, timeout_s):
        raise ValueError(f"refusing command outside fixed Tier 0 table: {check_id} {argv}")
    try:
        proc = subprocess.Popen(
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(MINIMAL_ENV),
        )
    except FileNotFoundError:
        return CommandResult(exit_code=None, missing_tool=True)
    return _read_capped(proc, timeout_s=timeout_s, cap_bytes=MAX_OUTPUT_BYTES)


def _classify_integrity_detail(detail: str) -> str:
    d = detail.strip().lower()
    if "permission denied" in d:
        return "permission-denied"
    if "no such file" in d or d == "missing" or "missing" in d:
        return "missing"
    if "permission" in d or "mode" in d:
        return "permissions"
    if "uid" in d or "gid" in d or "owner" in d or "group" in d:
        return "ownership"
    if "size" in d:
        return "size"
    if "modification time" in d or "mtime" in d:
        return "mtime"
    if "type" in d or "symlink" in d:
        return "type"
    return "other"


def _parse_integrity(res: CommandResult, hostname: str) -> tuple[str, str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    saw_permission = False
    saw_parse_error = False

    combined_lines = [
        line.strip()
        for stream in (res.stdout, res.stderr)
        for line in (stream or "").splitlines()
        if line.strip()
    ]
    for line in combined_lines:
        lower = line.lower()
        if "permission denied" in lower:
            saw_permission = True
            continue
        if INTEGRITY_SUMMARY_RE.match(line) or INTEGRITY_NO_MTREE_RE.match(line):
            continue
        m = INTEGRITY_WARNING_RE.match(line)
        if not m:
            saw_parse_error = True
            continue
        pkg, path, raw_details = m.group(1), m.group(2), m.group(3)
        parts = [p.strip() for p in re.split(r"[;,]", raw_details) if p.strip()]
        if not parts:
            saw_parse_error = True
            continue
        for part in parts:
            prop = _classify_integrity_detail(part)
            if prop == "permission-denied":
                saw_permission = True
                continue
            subject = f"{scrub_text(pkg, hostname, scrub_host=False)} {scrub_text(path, hostname)} {prop}"
            findings.append({
                "check": "integrity",
                "kind": "file-property",
                "subject": subject,
                "state": "mismatch",
                "attributes": {},
            })

    if saw_permission:
        return "partial", "permission", findings
    if res.exit_code not in (0, 1) or (res.exit_code == 1 and not findings):
        return "failed", "exit-status", []
    if saw_parse_error:
        return "partial", "parse", findings
    return "ok", "none", findings


def _parse_updates(res: CommandResult, hostname: str) -> tuple[str, str, list[dict[str, Any]]]:
    if _is_empty_result("updates", res):
        return "ok", "none", []
    if res.exit_code != 0:
        return "failed", "exit-status", []
    if (res.stderr or "").strip():
        return "partial", "parse", []
    findings: list[dict[str, Any]] = []
    saw_parse_error = False
    for raw in (res.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = UPDATES_RE.match(line)
        if not m:
            saw_parse_error = True
            continue
        pkg, installed_v, available_v = m.group(1), m.group(2), m.group(3)
        findings.append({
            "check": "updates",
            "kind": "local-update",
            "subject": scrub_text(pkg, hostname, scrub_host=False),
            "state": "available",
            "attributes": {
                "installed_version": scrub_text(installed_v, hostname, scrub_host=False),
                "available_version": scrub_text(available_v, hostname, scrub_host=False),
            },
        })
    if saw_parse_error:
        return "partial", "parse", findings
    return "ok", "none", findings


def _parse_pkg_list(
    check_id: str,
    kind: str,
    res: CommandResult,
    hostname: str,
) -> tuple[str, str, list[dict[str, Any]]]:
    if _is_empty_result(check_id, res):
        return "ok", "none", []
    if res.exit_code != 0:
        return "failed", "exit-status", []
    if (res.stderr or "").strip():
        return "partial", "parse", []
    findings: list[dict[str, Any]] = []
    saw_parse_error = False
    for raw in (res.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = PKG_VERSION_RE.match(line)
        if not m:
            saw_parse_error = True
            continue
        pkg, installed_v = m.group(1), m.group(2)
        findings.append({
            "check": check_id,
            "kind": kind,
            "subject": scrub_text(pkg, hostname, scrub_host=False),
            "state": "present",
            "attributes": {
                "installed_version": scrub_text(installed_v, hostname, scrub_host=False),
            },
        })
    if saw_parse_error:
        return "partial", "parse", findings
    return "ok", "none", findings


def _parse_pacdiff(res: CommandResult, hostname: str) -> tuple[str, str, list[dict[str, Any]]]:
    if res.exit_code != 0:
        return "failed", "exit-status", []
    if (res.stderr or "").strip():
        return "partial", "parse", []
    findings: list[dict[str, Any]] = []
    saw_parse_error = False
    for raw in (res.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = PACDIFF_RE.match(line)
        if not m:
            saw_parse_error = True
            continue
        path = m.group(1)
        findings.append({
            "check": "pacdiff",
            "kind": "pending-config",
            "subject": scrub_text(path, hostname),
            "state": "present",
            "attributes": {},
        })
    if saw_parse_error:
        return "partial", "parse", findings
    return "ok", "none", findings


def _parse_failed_units(res: CommandResult, hostname: str) -> tuple[str, str, list[dict[str, Any]]]:
    if res.exit_code != 0:
        return "failed", "exit-status", []
    if (res.stderr or "").strip():
        return "partial", "parse", []
    findings: list[dict[str, Any]] = []
    saw_parse_error = False
    for raw in (res.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = FAILED_UNIT_RE.match(line)
        if not m:
            saw_parse_error = True
            continue
        unit, load, active, sub = m.group(1), m.group(2), m.group(3), m.group(4)
        findings.append({
            "check": "failed-units",
            "kind": "failed-unit",
            "subject": scrub_text(unit, hostname),
            "state": "failed",
            "attributes": {
                "load": scrub_text(load, hostname),
                "active": scrub_text(active, hostname),
                "sub": scrub_text(sub, hostname),
            },
        })
    if saw_parse_error:
        return "partial", "parse", findings
    return "ok", "none", findings


def hash_paclog_lines(lines: list[str]) -> str:
    """Compute canonical SHA-256 of `lines` with LF line terminators."""
    payload = "".join(f"{line}\n" for line in lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _parse_paclog_entry(line: str) -> tuple[str, dt.datetime, str, str] | None:
    m = PACLOG_LINE_RE.match(line)
    if not m:
        return None
    ts_str, caller, msg = m.group(1), m.group(2), m.group(3)
    try:
        parsed_dt = dt.datetime.fromisoformat(ts_str)
    except ValueError:
        return None
    if parsed_dt.tzinfo is None:
        return None
    return ts_str, parsed_dt.astimezone(dt.timezone.utc), caller, msg


def _parse_paclog(
    res: CommandResult,
    hostname: str,
    previous_cursor: dict[str, Any] | None,
    now_utc: dt.datetime,
) -> tuple[str, str, list[dict[str, Any]], dict[str, Any] | None]:
    if res.exit_code != 0:
        return "failed", "exit-status", [], previous_cursor
    if (res.stderr or "").strip():
        return "partial", "parse", [], previous_cursor

    raw_lines = [line for line in (res.stdout or "").splitlines() if line != ""]
    new_cursor = {
        "lines": len(raw_lines),
        "prefix_sha256": hash_paclog_lines(raw_lines),
    }

    log_gap = False
    use_24h_window = True
    window_lines = raw_lines

    if previous_cursor is not None:
        prev_lines = previous_cursor["lines"]
        prev_hash = previous_cursor["prefix_sha256"]
        if len(raw_lines) >= prev_lines and hash_paclog_lines(raw_lines[:prev_lines]) == prev_hash:
            window_lines = raw_lines[prev_lines:]
            use_24h_window = False
        else:
            log_gap = True
            use_24h_window = True
            window_lines = raw_lines

    saw_parse_error = False
    for line in raw_lines:
        if _parse_paclog_entry(line) is None:
            saw_parse_error = True

    cutoff_utc = now_utc.astimezone(dt.timezone.utc) - dt.timedelta(hours=24)
    findings: list[dict[str, Any]] = []
    for line in window_lines:
        parsed = _parse_paclog_entry(line)
        if parsed is None:
            saw_parse_error = True
            continue
        ts_str, entry_utc, _caller, msg = parsed
        if use_24h_window and entry_utc < cutoff_utc:
            continue
        msg_stripped = msg.strip()
        if any(msg_stripped.startswith(prefix) for prefix in PACLOG_WARNING_PREFIXES):
            subject = f"{scrub_text(ts_str, hostname)} {scrub_text(msg_stripped, hostname)}"
            findings.append({
                "check": "paclog",
                "kind": "log-warning",
                "subject": subject,
                "state": "observed",
                "attributes": {},
            })

    if log_gap:
        return "partial", "log-gap", findings, new_cursor
    if saw_parse_error:
        return "partial", "parse", findings, new_cursor
    return "ok", "none", findings, new_cursor


def _dedupe_and_sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for f in findings:
        key = (f["check"], f["kind"], f["subject"])
        by_key[key] = {
            "check": f["check"],
            "kind": f["kind"],
            "subject": f["subject"],
            "state": f["state"],
            "attributes": dict(sorted(f["attributes"].items())),
        }
    return [by_key[k] for k in sorted(by_key)]


def _iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_snapshot(data: Any) -> dict[str, Any]:
    """Validate a snapshot dict against schema version 1; reject unknown fields."""
    if not isinstance(data, dict):
        raise ValueError("snapshot must be a JSON object")
    expected_top = {
        "schema_version",
        "simulation",
        "started_at",
        "finished_at",
        "checks",
        "findings",
        "paclog_cursor",
    }
    extra_top = set(data.keys()) - expected_top
    missing_top = expected_top - set(data.keys())
    if extra_top:
        raise ValueError(f"unknown top-level field(s): {sorted(extra_top)}")
    if missing_top:
        raise ValueError(f"missing top-level field(s): {sorted(missing_top)}")

    if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {data['schema_version']!r}")
    if type(data["simulation"]) is not bool:
        raise ValueError("simulation must be a boolean")
    for ts_field in ("started_at", "finished_at"):
        val = data[ts_field]
        if not isinstance(val, str) or not val:
            raise ValueError(f"{ts_field} must be a non-empty ISO-8601 string")
        try:
            parsed = dt.datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid {ts_field}: {val!r}") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{ts_field} must include UTC timezone offset")

    cursor = data["paclog_cursor"]
    if cursor is not None:
        if not isinstance(cursor, dict):
            raise ValueError("paclog_cursor must be an object or null")
        if set(cursor.keys()) != {"lines", "prefix_sha256"}:
            raise ValueError(f"invalid paclog_cursor fields: {sorted(cursor.keys())}")
        if type(cursor["lines"]) is not int or cursor["lines"] < 0:
            raise ValueError("paclog_cursor.lines must be a non-negative integer")
        if not isinstance(cursor["prefix_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", cursor["prefix_sha256"]):
            raise ValueError("paclog_cursor.prefix_sha256 must be a 64-char lowercase hex sha256")

    checks = data["checks"]
    if not isinstance(checks, list):
        raise ValueError("checks must be a list")
    seen_checks: set[str] = set()
    for c in checks:
        if not isinstance(c, dict):
            raise ValueError("each check record must be an object")
        expected_check_keys = {"check", "status", "reason", "exit_code"}
        if set(c.keys()) != expected_check_keys:
            raise ValueError(f"invalid check record keys: {sorted(c.keys())}")
        cid = c["check"]
        if cid not in CHECK_IDS:
            raise ValueError(f"unknown check id: {cid!r}")
        if cid in seen_checks:
            raise ValueError(f"duplicate check id: {cid!r}")
        seen_checks.add(cid)
        if c["status"] not in CHECK_STATUSES:
            raise ValueError(f"invalid check status: {c['status']!r}")
        if c["reason"] not in CHECK_REASONS:
            raise ValueError(f"invalid check reason: {c['reason']!r}")
        if c["status"] == "ok" and c["reason"] != "none":
            raise ValueError(f"check {cid} is ok but reason is {c['reason']!r}")
        if c["status"] != "ok" and c["reason"] == "none":
            raise ValueError(f"check {cid} is {c['status']} but reason is 'none'")
        ec = c["exit_code"]
        if ec is not None and type(ec) is not int:
            raise ValueError(f"check {cid} exit_code must be int or null")
    if seen_checks != set(CHECK_IDS):
        raise ValueError(f"checks must contain all 7 Tier 0 checks; missing {sorted(set(CHECK_IDS) - seen_checks)}")

    findings = data["findings"]
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    seen_keys: set[tuple[str, str, str]] = set()
    for f in findings:
        if not isinstance(f, dict):
            raise ValueError("each finding must be an object")
        expected_finding_keys = {"check", "kind", "subject", "state", "attributes"}
        if set(f.keys()) != expected_finding_keys:
            raise ValueError(f"invalid finding keys: {sorted(f.keys())}")
        cid = f["check"]
        if cid not in FINDING_SCHEMA:
            raise ValueError(f"unknown finding check: {cid!r}")
        for s_key in ("check", "kind", "subject", "state"):
            if not isinstance(f[s_key], str) or not f[s_key].strip():
                raise ValueError(f"finding.{s_key} must be a non-empty string")
        exp_kind, exp_state, exp_attrs = FINDING_SCHEMA[cid]
        if f["kind"] != exp_kind:
            raise ValueError(f"finding for {cid} must have kind {exp_kind!r}, got {f['kind']!r}")
        if f["state"] != exp_state:
            raise ValueError(f"finding for {cid} must have state {exp_state!r}, got {f['state']!r}")
        attrs = f["attributes"]
        if not isinstance(attrs, dict):
            raise ValueError("finding.attributes must be an object")
        if set(attrs.keys()) != exp_attrs:
            raise ValueError(f"finding for {cid} must have attributes {sorted(exp_attrs)}, got {sorted(attrs.keys())}")
        for ak, av in attrs.items():
            if not isinstance(ak, str) or not isinstance(av, str) or not av:
                raise ValueError(f"finding attribute {ak!r} must be a non-empty string")
        if cid == "integrity":
            parts = f["subject"].split(" ")
            if len(parts) < 3 or parts[-1] not in INTEGRITY_PROPERTIES:
                raise ValueError(f"invalid integrity subject {f['subject']!r}")
        fkey = (f["check"], f["kind"], f["subject"])
        if fkey in seen_keys:
            raise ValueError(f"duplicate finding key: {fkey!r}")
        seen_keys.add(fkey)

    return data


def collect_snapshot(
    *,
    previous_snapshot: dict[str, Any] | None = None,
    runner: Callable[[str, tuple[str, ...], int], CommandResult] = run_tier0_command,
    hostname: str | None = None,
    now_utc: dt.datetime | None = None,
    simulation: bool = False,
) -> dict[str, Any]:
    """Run all 7 Tier 0 checks via `runner` and return a validated snapshot dict."""
    prev_cursor: dict[str, Any] | None = None
    if previous_snapshot is not None:
        validate_snapshot(previous_snapshot)
        prev_cursor = previous_snapshot["paclog_cursor"]

    host = hostname if hostname is not None else socket.gethostname()
    started = (now_utc or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)

    checks_out: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    next_cursor: dict[str, Any] | None = prev_cursor

    for check_id, argv, timeout_s in COMMAND_TABLE:
        res = runner(check_id, argv, timeout_s)
        if res.missing_tool:
            checks_out.append({
                "check": check_id,
                "status": "failed",
                "reason": "missing-tool",
                "exit_code": None,
            })
            continue
        if res.timed_out:
            checks_out.append({
                "check": check_id,
                "status": "failed",
                "reason": "timeout",
                "exit_code": None,
            })
            continue
        if res.truncated:
            checks_out.append({
                "check": check_id,
                "status": "failed",
                "reason": "truncated",
                "exit_code": res.exit_code,
            })
            continue

        if check_id == "integrity":
            status, reason, findings = _parse_integrity(res, host)
        elif check_id == "paclog":
            status, reason, findings, next_cursor = _parse_paclog(res, host, prev_cursor, started)
        elif check_id == "updates":
            status, reason, findings = _parse_updates(res, host)
        elif check_id == "foreign":
            status, reason, findings = _parse_pkg_list("foreign", "foreign-package", res, host)
        elif check_id == "orphans":
            status, reason, findings = _parse_pkg_list("orphans", "orphan-package", res, host)
        elif check_id == "pacdiff":
            status, reason, findings = _parse_pacdiff(res, host)
        elif check_id == "failed-units":
            status, reason, findings = _parse_failed_units(res, host)
        else:
            raise AssertionError(f"unreachable check_id: {check_id}")

        checks_out.append({
            "check": check_id,
            "status": status,
            "reason": reason,
            "exit_code": res.exit_code,
        })
        all_findings.extend(findings)

    finished = (now_utc or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "simulation": bool(simulation),
        "started_at": _iso_utc(started),
        "finished_at": _iso_utc(finished),
        "checks": checks_out,
        "findings": _dedupe_and_sort_findings(all_findings),
        "paclog_cursor": next_cursor,
    }
    return validate_snapshot(snapshot)


def write_snapshot_file(
    snapshot: dict[str, Any],
    out_dir: str | Path,
    *,
    filename: str | None = None,
    root: Path | None = None,
) -> Path:
    """Write `snapshot` to a temporary file in `out_dir` and rename without overwriting."""
    validate_snapshot(snapshot)
    resolved_dir = check_out_dir(out_dir, root=root)
    resolved_dir.mkdir(parents=True, exist_ok=True)

    if filename is not None:
        target = resolved_dir / filename
        if target.exists():
            raise FileExistsError(f"refusing to overwrite existing snapshot file: {target}")
    else:
        stamp = snapshot["started_at"].replace("-", "").replace(":", "")
        base_name = f"snapshot-{stamp}"
        candidate = resolved_dir / f"{base_name}.json"
        seq = 2
        while candidate.exists():
            candidate = resolved_dir / f"{base_name}-{seq}.json"
            seq += 1
        target = candidate

    payload = json.dumps(snapshot, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-snapshot-", suffix=".json", dir=str(resolved_dir))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists():
            raise FileExistsError(f"refusing to overwrite existing snapshot file: {target}")
        os.replace(tmp_path, target)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Tier 0 system health scan collector (offline, unprivileged, read-only)")
    ap.add_argument("--out", required=True, help="Output directory outside the repository")
    ap.add_argument("--previous", help="Previous snapshot JSON file for paclog cursor continuity")
    args = ap.parse_args(argv)

    try:
        out_dir = check_out_dir(args.out)
        prev_data = None
        if args.previous:
            prev_path = Path(args.previous).expanduser()
            prev_data = validate_snapshot(json.loads(prev_path.read_text(encoding="utf-8")))
        snapshot = collect_snapshot(previous_snapshot=prev_data)
        written = write_snapshot_file(snapshot, out_dir)
    except Exception as exc:
        print(f"collect.py error: {exc}", file=sys.stderr)
        return 1

    print(str(written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
