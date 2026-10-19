"""Unit tests for the Tier 0 system health scan collector and diff (M04 task 4).

Run from repo root:
  python -I -m unittest discover -s projects/health-scan/tests

Uses SIMULATED fixtures only; never runs the collector against the real system.
"""
from __future__ import annotations

import ast
import copy
import datetime as dt
import io
import json
import random
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent
REPO_ROOT = PROJECT_DIR.parents[1]
FIXTURES_DIR = TESTS_DIR / "fixtures"

sys.path.insert(0, str(PROJECT_DIR))

import collect  # noqa: E402
import diff  # noqa: E402


def load_fixture(name: str) -> dict[str, Any]:
    path = FIXTURES_DIR / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("simulation") is not True:
        raise AssertionError(f"fixture {path} must have simulation=True")
    return data


def make_runner_from_commands(commands: dict[str, dict[str, Any]]):
    def _runner(check_id: str, argv: tuple[str, ...], timeout_s: int) -> collect.CommandResult:
        spec = commands.get(check_id, {"stdout": "", "stderr": "", "exit_code": 0})
        return collect.CommandResult(
            stdout=spec.get("stdout", ""),
            stderr=spec.get("stderr", ""),
            exit_code=spec.get("exit_code", 0),
            missing_tool=spec.get("missing_tool", False),
            timed_out=spec.get("timed_out", False),
            truncated=spec.get("truncated", False),
        )

    return _runner


class HealthScanTests(unittest.TestCase):
    def test_all_fixture_files_marked_simulated(self):
        fixture_files = sorted(FIXTURES_DIR.glob("*.json"))
        self.assertEqual(
            [p.stem for p in fixture_files],
            [
                "boundary",
                "clean",
                "diff",
                "failures",
                "findings",
                "paclog-cursor",
                "paclog-offsets",
                "scrub",
            ],
        )
        for path in fixture_files:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIs(data.get("simulation"), True, f"{path.name} missing simulation: true")

    def test_boundary_command_table_and_no_shell_or_repo_writes(self):
        fx = load_fixture("boundary")
        actual = [
            {"check": cid, "argv": list(argv), "timeout": timeout}
            for cid, argv, timeout in collect.COMMAND_TABLE
        ]
        self.assertEqual(actual, fx["expected_command_table"])

        # Verify no forbidden binaries or --after filter in command table
        for _cid, argv, _tmo in collect.COMMAND_TABLE:
            self.assertNotIn(argv[0], fx["forbidden_binaries"])
            self.assertNotIn("--after", argv)

        # Static AST verification of collect.py and diff.py (AC2)
        collect_tree = ast.parse((PROJECT_DIR / "collect.py").read_text(encoding="utf-8"))
        diff_tree = ast.parse((PROJECT_DIR / "diff.py").read_text(encoding="utf-8"))

        for node in ast.walk(diff_tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names]
                self.assertNotIn("subprocess", names)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotEqual(node.module, "subprocess")

        popen_calls = []
        for node in ast.walk(collect_tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    popen_calls.append((node.func.attr, node))
        self.assertEqual([name for name, _ in popen_calls], ["Popen"])
        _, popen_node = popen_calls[0]
        kw = {k.arg: k.value for k in popen_node.keywords}
        self.assertIsInstance(kw.get("shell"), ast.Constant)
        self.assertIs(kw["shell"].value, False)

        # Refuses any command outside the fixed Tier 0 table
        with self.assertRaises(ValueError):
            collect.run_tier0_command("integrity", ("pacman", "-Sy"), 300)
        with self.assertRaises(ValueError):
            collect.run_tier0_command("unknown", ("pacman", "-Qu"), 60)

        # Refuses --out inside the repository (AC3)
        for rel in fx["repo_relative_out_paths_to_refuse"]:
            inside = REPO_ROOT / rel
            with self.assertRaises(ValueError):
                collect.check_out_dir(inside, root=REPO_ROOT)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = collect.main(["--out", str(inside)])
            self.assertEqual(rc, 1)
            self.assertIn("inside repository", stderr.getvalue())

        # Also refuses a symlink outside the repo that points inside the repo
        with tempfile.TemporaryDirectory(prefix="hs-boundary-") as tmp:
            link_path = Path(tmp) / "link-into-repo"
            link_path.symlink_to(REPO_ROOT / "projects")
            with self.assertRaises(ValueError):
                collect.check_out_dir(link_path / "sub", root=REPO_ROOT)

    def test_clean_fixture_all_ok_zero_findings(self):
        fx = load_fixture("clean")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))
        snap = collect.collect_snapshot(
            runner=make_runner_from_commands(fx["commands"]),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        self.assertEqual(snap["schema_version"], 1)
        self.assertIs(snap["simulation"], True)
        self.assertEqual(snap["findings"], [])
        self.assertEqual(len(snap["checks"]), 7)
        for chk in snap["checks"]:
            self.assertEqual(chk["status"], "ok")
            self.assertEqual(chk["reason"], "none")
            self.assertEqual(chk["exit_code"], 0)
        self.assertEqual(snap["paclog_cursor"]["lines"], 4)
        self.assertRegex(snap["paclog_cursor"]["prefix_sha256"], r"^[0-9a-f]{64}$")

    def test_findings_fixture_parses_all_seven_checks_and_integrity_properties(self):
        fx = load_fixture("findings")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))
        snap = collect.collect_snapshot(
            runner=make_runner_from_commands(fx["commands"]),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        for chk in snap["checks"]:
            self.assertEqual(chk["status"], "ok", f"check {chk['check']} was not ok")

        by_check: dict[str, list[dict[str, Any]]] = {cid: [] for cid in collect.CHECK_IDS}
        for f in snap["findings"]:
            by_check[f["check"]].append(f)

        for cid in collect.CHECK_IDS:
            self.assertGreaterEqual(len(by_check[cid]), 1, f"expected findings for {cid}")

        integrity_props = {f["subject"].split(" ")[-1] for f in by_check["integrity"]}
        self.assertEqual(
            integrity_props,
            {"missing", "permissions", "ownership", "size", "mtime", "type", "other"},
        )
        self.assertIn(
            {
                "check": "updates",
                "kind": "local-update",
                "subject": "linux",
                "state": "available",
                "attributes": {
                    "available_version": "6.11.4.arch1-1",
                    "installed_version": "6.11.3.arch1-1",
                },
            },
            by_check["updates"],
        )
        self.assertIn(
            {
                "check": "foreign",
                "kind": "foreign-package",
                "subject": "yay-bin",
                "state": "present",
                "attributes": {"installed_version": "12.4.2-1"},
            },
            by_check["foreign"],
        )
        self.assertIn(
            {
                "check": "orphans",
                "kind": "orphan-package",
                "subject": "go-md2man",
                "state": "present",
                "attributes": {"installed_version": "2.0.4-1"},
            },
            by_check["orphans"],
        )
        pacdiff_subjects = [f["subject"] for f in by_check["pacdiff"]]
        self.assertEqual(
            pacdiff_subjects,
            [
                "/etc/mkinitcpio.conf.pacsave",
                "/etc/pacman.conf.pacnew",
                "/etc/shadow.pacorig",
            ],
        )
        self.assertIn(
            {
                "check": "failed-units",
                "kind": "failed-unit",
                "subject": "logrotate.service",
                "state": "failed",
                "attributes": {"active": "failed", "load": "loaded", "sub": "failed"},
            },
            by_check["failed-units"],
        )
        paclog_subjects = [f["subject"] for f in by_check["paclog"]]
        self.assertEqual(len(paclog_subjects), 3)

    def test_scrub_fixture_removes_mac_uuid_hostname_and_drops_serial(self):
        fx = load_fixture("scrub")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))
        snap = collect.collect_snapshot(
            runner=make_runner_from_commands(fx["commands"]),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        serialized = json.dumps(snap)
        for sentinel in fx["sentinels"]:
            self.assertNotIn(sentinel.lower(), serialized.lower(), f"sentinel {sentinel!r} leaked")

        self.assertEqual(len(snap["findings"]), 7)
        for f in snap["findings"]:
            combined = f["subject"] + " " + " ".join(f["attributes"].values())
            if f["check"] not in ("updates", "foreign", "orphans"):   # package fields skip host scrub (D-039)
                self.assertIn("<host>", combined)
            self.assertIn("<mac>", combined)
            self.assertIn("<uuid>", combined)

    def test_hostname_scrub_spares_package_names(self):
        """D-039: hostname `archlinux` must not rewrite package `archlinux-keyring`. Simulated output."""
        cmds = {
            "updates": {"stdout": "archlinux-keyring 20260901-1 -> 20261001-1\n"},
            "foreign": {"stdout": "archlinux-tools 1.0-1\n"},
            "integrity": {"stdout": "warning: archlinux-keyring: /etc/archlinux/x (Size mismatch)\n"},
            "failed-units": {"stdout": "netctl@archlinux-wlan.service loaded failed failed\n"},
        }
        snap = collect.collect_snapshot(runner=make_runner_from_commands(cmds), hostname="archlinux",
                                        now_utc=dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc), simulation=True)
        subjects = {f["check"]: f["subject"] for f in snap["findings"]}
        self.assertEqual(subjects["updates"], "archlinux-keyring")
        self.assertEqual(subjects["foreign"], "archlinux-tools")
        self.assertEqual(subjects["integrity"], "archlinux-keyring /etc/<host>/x size")   # package kept, path scrubbed
        self.assertEqual(subjects["failed-units"], "netctl@<host>-wlan.service")

    def test_exit_one_with_no_output_is_an_empty_result(self):
        """D-039: `pacman -Qu` exits 1 with no output when nothing is pending (observed). Simulated output."""
        for check in ("updates", "foreign", "orphans"):
            snap = collect.collect_snapshot(
                runner=make_runner_from_commands({check: {"stdout": "", "stderr": "", "exit_code": 1}}),
                hostname="h", now_utc=dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc), simulation=True)
            chk = next(c for c in snap["checks"] if c["check"] == check)
            self.assertEqual((chk["status"], chk["reason"], chk["exit_code"]), ("ok", "none", 1), check)
            # Exit 1 with an error message is still a failure.
            snap = collect.collect_snapshot(
                runner=make_runner_from_commands({check: {"stderr": "error: failed to read db\n", "exit_code": 1}}),
                hostname="h", now_utc=dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc), simulation=True)
            chk = next(c for c in snap["checks"] if c["check"] == check)
            self.assertEqual((chk["status"], chk["reason"]), ("failed", "exit-status"), check)
        # Other checks keep treating exit 1 as a failure.
        snap = collect.collect_snapshot(runner=make_runner_from_commands({"pacdiff": {"exit_code": 1}}),
                                        hostname="h", now_utc=dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc),
                                        simulation=True)
        self.assertEqual(next(c for c in snap["checks"] if c["check"] == "pacdiff")["status"], "failed")

    def test_integrity_exit_one_counts_only_with_parsed_mismatches(self):
        """D-039: `pacman -Qkk` is assumed to exit 1 when it reports mismatches (unverified). Simulated output."""
        now = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)
        out = "warning: filesystem: /etc/hosts (Modification time mismatch)\nfilesystem: 120 total files, 1 altered file\n"
        cases = [({"stdout": out, "exit_code": 1}, "ok", 1),
                 ({"stdout": "", "exit_code": 1}, "failed", 0),
                 ({"stdout": out, "exit_code": 2}, "failed", 0)]
        for spec, status, n in cases:
            snap = collect.collect_snapshot(runner=make_runner_from_commands({"integrity": spec}),
                                            hostname="h", now_utc=now, simulation=True)
            self.assertEqual(next(c for c in snap["checks"] if c["check"] == "integrity")["status"], status, spec)
            self.assertEqual(len([f for f in snap["findings"] if f["check"] == "integrity"]), n, spec)

    def test_paclog_offsets_uses_true_utc_for_24h_baseline(self):
        fx = load_fixture("paclog-offsets")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))
        commands = {"paclog": {"stdout": fx["paclog_stdout"], "stderr": "", "exit_code": 0}}
        snap = collect.collect_snapshot(
            runner=make_runner_from_commands(commands),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk = next(c for c in snap["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk["status"], "ok")
        self.assertEqual(paclog_chk["reason"], "none")
        subjects = [f["subject"] for f in snap["findings"] if f["check"] == "paclog"]
        self.assertEqual(subjects, sorted(fx["expected_subjects"]))

    def test_paclog_cursor_append_empty_rotation_truncation_and_failure(self):
        fx = load_fixture("paclog-cursor")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))

        # 1. Baseline run (2 lines, 1 warning)
        snap1 = collect.collect_snapshot(
            runner=make_runner_from_commands(
                {"paclog": {"stdout": fx["baseline_stdout"], "stderr": "", "exit_code": 0}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        self.assertEqual(snap1["paclog_cursor"]["lines"], 2)
        self.assertEqual(
            [f["subject"] for f in snap1["findings"] if f["check"] == "paclog"],
            ["2026-10-19T01:01:00-0600 warning: baseline warning within 24h"],
        )

        # 2. Appended run (4 lines, same 2-line prefix) -> selects only appended warning
        snap2 = collect.collect_snapshot(
            previous_snapshot=snap1,
            runner=make_runner_from_commands(
                {"paclog": {"stdout": fx["appended_stdout"], "stderr": "", "exit_code": 0}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk2 = next(c for c in snap2["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk2["status"], "ok")
        self.assertEqual(paclog_chk2["reason"], "none")
        self.assertEqual(snap2["paclog_cursor"]["lines"], 4)
        self.assertEqual(
            [f["subject"] for f in snap2["findings"] if f["check"] == "paclog"],
            ["2026-10-19T05:01:00-0600 warning: appended warning after cursor"],
        )

        # 3. Same 4 lines, no append -> empty window
        snap3 = collect.collect_snapshot(
            previous_snapshot=snap2,
            runner=make_runner_from_commands(
                {"paclog": {"stdout": fx["appended_stdout"], "stderr": "", "exit_code": 0}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk3 = next(c for c in snap3["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk3["status"], "ok")
        self.assertEqual(paclog_chk3["reason"], "none")
        self.assertEqual([f for f in snap3["findings"] if f["check"] == "paclog"], [])

        # 4. Rotated log (different prefix hash) -> partial / log-gap, falls back to 24h window
        snap4 = collect.collect_snapshot(
            previous_snapshot=snap2,
            runner=make_runner_from_commands(
                {"paclog": {"stdout": fx["rotated_stdout"], "stderr": "", "exit_code": 0}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk4 = next(c for c in snap4["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk4["status"], "partial")
        self.assertEqual(paclog_chk4["reason"], "log-gap")
        self.assertEqual(
            [f["subject"] for f in snap4["findings"] if f["check"] == "paclog"],
            ["2026-10-19T04:30:00-0600 error: error in rotated log within 24h"],
        )

        # 5. Truncated log (fewer lines than cursor) -> partial / log-gap
        snap5 = collect.collect_snapshot(
            previous_snapshot=snap2,
            runner=make_runner_from_commands(
                {"paclog": {"stdout": fx["truncated_stdout"], "stderr": "", "exit_code": 0}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk5 = next(c for c in snap5["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk5["status"], "partial")
        self.assertEqual(paclog_chk5["reason"], "log-gap")
        self.assertEqual(
            [f["subject"] for f in snap5["findings"] if f["check"] == "paclog"],
            ["2026-10-19T05:30:00-0600 note: note in truncated 1-line log within 24h"],
        )

        # 6. Failed paclog run preserves previous cursor unchanged
        snap6 = collect.collect_snapshot(
            previous_snapshot=snap2,
            runner=make_runner_from_commands(
                {"paclog": {"stdout": "", "stderr": "error", "exit_code": 1}}
            ),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )
        paclog_chk6 = next(c for c in snap6["checks"] if c["check"] == "paclog")
        self.assertEqual(paclog_chk6["status"], "failed")
        self.assertEqual(paclog_chk6["reason"], "exit-status")
        self.assertEqual(snap6["paclog_cursor"], snap2["paclog_cursor"])

    def test_failures_fixture_statuses_and_never_false_resolved(self):
        fx = load_fixture("failures")
        findings_fx = load_fixture("findings")
        now_utc = dt.datetime.fromisoformat(fx["reference_now_utc"].replace("Z", "+00:00"))

        baseline = collect.collect_snapshot(
            runner=make_runner_from_commands(findings_fx["commands"]),
            hostname=fx["hostname"],
            now_utc=now_utc,
            simulation=True,
        )

        for case_name, case in fx["cases"].items():
            target_check = case["check"]
            cmds = copy.deepcopy(findings_fx["commands"])
            cmds[target_check] = {
                "stdout": case.get("stdout", ""),
                "stderr": case.get("stderr", ""),
                "exit_code": case.get("exit_code", 0),
                "missing_tool": case.get("missing_tool", False),
                "timed_out": case.get("timed_out", False),
                "truncated": case.get("truncated", False),
            }
            snap = collect.collect_snapshot(
                runner=make_runner_from_commands(cmds),
                hostname=fx["hostname"],
                now_utc=now_utc,
                simulation=True,
            )
            chk = next(c for c in snap["checks"] if c["check"] == target_check)
            self.assertEqual(chk["status"], case["expected_status"], f"case {case_name}")
            self.assertEqual(chk["reason"], case["expected_reason"], f"case {case_name}")

            # Diffing baseline (with findings) against a failed/partial check never produces resolved
            d = diff.diff_snapshots(baseline, snap)
            self.assertEqual(d["by_check"][target_check]["tool-failure"], 1, f"case {case_name}")
            self.assertEqual(d["by_check"][target_check]["resolved"], 0, f"case {case_name}")
            self.assertEqual(d["by_check"][target_check]["new"], 0, f"case {case_name}")
            self.assertEqual(d["by_check"][target_check]["changed"], 0, f"case {case_name}")

    def test_diff_fixture_classes_determinism_shuffle_and_cli(self):
        fx = load_fixture("diff")
        snap_a = fx["snapshot_a"]
        snap_b = fx["snapshot_b"]

        # AC6: new / resolved / changed / tool-failure counts match fixture; paclog never resolved
        res = diff.diff_snapshots(snap_a, snap_b)
        self.assertEqual(res, fx["expected_diff"])

        # AC5: A vs A gives zero for every finding class
        same = diff.diff_snapshots(snap_a, snap_a)
        self.assertEqual(
            same["totals"],
            {"changed": 0, "new": 0, "resolved": 0, "tool-failure": 0},
        )
        for cid in collect.CHECK_IDS:
            self.assertEqual(
                same["by_check"][cid],
                {"changed": 0, "new": 0, "resolved": 0, "tool-failure": 0},
            )

        # AC5: shuffled findings/checks and altered timestamps/cursors give identical output
        rng = random.Random(42)
        shuffled_a = copy.deepcopy(snap_a)
        shuffled_b = copy.deepcopy(snap_b)
        rng.shuffle(shuffled_a["findings"])
        rng.shuffle(shuffled_a["checks"])
        rng.shuffle(shuffled_b["findings"])
        rng.shuffle(shuffled_b["checks"])
        shuffled_a["started_at"] = "2026-10-01T00:00:00Z"
        shuffled_b["paclog_cursor"] = None

        out1 = diff.format_diff(res)
        out2 = diff.format_diff(diff.diff_snapshots(shuffled_a, shuffled_b))
        self.assertEqual(out1, out2)

        # Output contains no paths, unit names, or messages
        for forbidden in ("/etc/pacman.conf", "logrotate.service", "yay-bin", "go-md2man", "warning:"):
            self.assertNotIn(forbidden, out1)

        # Test write_snapshot_file (no overwrite) and CLI diff.main
        with tempfile.TemporaryDirectory(prefix="hs-diff-") as tmp:
            path_a = collect.write_snapshot_file(snap_a, tmp, filename="a.json")
            path_b = collect.write_snapshot_file(snap_b, tmp, filename="b.json")
            with self.assertRaises(FileExistsError):
                collect.write_snapshot_file(snap_a, tmp, filename="a.json")

            # Auto-named snapshots never overwrite each other even with identical timestamps
            auto1 = collect.write_snapshot_file(snap_a, tmp)
            auto2 = collect.write_snapshot_file(snap_a, tmp)
            self.assertNotEqual(auto1, auto2)
            self.assertTrue(auto1.is_file())
            self.assertTrue(auto2.is_file())

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = diff.main([str(path_a), str(path_b)])
            self.assertEqual(rc, 0)
            self.assertEqual(stdout.getvalue(), out1)

    def test_schema_validation_rejects_unknown_fields_and_mismatched_simulation(self):
        fx = load_fixture("diff")
        valid = copy.deepcopy(fx["snapshot_a"])
        collect.validate_snapshot(valid)

        # Unknown top-level field
        bad_top = copy.deepcopy(valid)
        bad_top["extra"] = 1
        with self.assertRaises(ValueError):
            collect.validate_snapshot(bad_top)

        # Unknown check field
        bad_chk = copy.deepcopy(valid)
        bad_chk["checks"][0]["extra"] = "x"
        with self.assertRaises(ValueError):
            collect.validate_snapshot(bad_chk)

        # Unknown finding field
        bad_find = copy.deepcopy(valid)
        bad_find["findings"][0]["extra"] = "x"
        with self.assertRaises(ValueError):
            collect.validate_snapshot(bad_find)

        # Unknown attribute key
        bad_attr = copy.deepcopy(valid)
        bad_attr["findings"][0]["attributes"]["extra"] = "x"
        with self.assertRaises(ValueError):
            collect.validate_snapshot(bad_attr)

        # Mismatched simulation flag rejected by diff
        non_sim = copy.deepcopy(valid)
        non_sim["simulation"] = False
        with self.assertRaises(ValueError):
            diff.diff_snapshots(valid, non_sim)


class ReaderAndPublishTests(unittest.TestCase):
    """Inspector findings 1–2 (Codex, 2026-10-19). Children are local Python one-liners
    printing simulated output; no Tier 0 command runs."""

    def child(self, code: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_reader_returns_both_streams_and_exit_code(self):
        res = collect._read_capped(self.child("import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"),
                                   timeout_s=10, cap_bytes=1024)
        self.assertEqual((res.stdout, res.stderr, res.exit_code, res.truncated), ("out\n", "err\n", 3, False))

    def test_reader_stops_child_at_cap_with_bounded_memory(self):
        # The child would write 50 MiB and then sleep; the reader must stop it near the cap.
        proc = self.child("import sys, time\nfor _ in range(800): sys.stdout.write('x' * 65536)\n"
                          "sys.stdout.flush(); time.sleep(30)")
        res = collect._read_capped(proc, timeout_s=10, cap_bytes=256 * 1024)
        self.assertTrue(res.truncated)
        self.assertLessEqual(len(res.stdout), 256 * 1024)
        self.assertIsNotNone(proc.returncode)   # reaped, not left running

    def test_reader_cap_counts_both_streams(self):
        proc = self.child("import sys\nsys.stdout.write('o' * 3000); sys.stdout.flush()\n"
                          "sys.stderr.write('e' * 3000); sys.stderr.flush()")
        self.assertTrue(collect._read_capped(proc, timeout_s=10, cap_bytes=4000).truncated)

    def test_reader_times_out_and_reaps(self):
        proc = self.child("import time; time.sleep(30)")
        res = collect._read_capped(proc, timeout_s=0.5, cap_bytes=1024)
        self.assertTrue(res.timed_out)
        self.assertIsNotNone(proc.returncode)

    def snapshot(self) -> dict[str, Any]:
        return collect.collect_snapshot(runner=make_runner_from_commands({}), hostname="h",
                                        now_utc=dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc), simulation=True)

    def test_publish_never_overwrites_a_file_created_during_the_race(self):
        snap = self.snapshot()
        real_link = collect.os.link
        with tempfile.TemporaryDirectory(prefix="hs-race-") as tmp:
            first = Path(tmp) / "snapshot-20261019T000000Z.json"

            def racing_link(src, dst):
                # Another run creates the target between "name chosen" and "publish".
                if Path(dst) == first and not first.exists():
                    first.write_text("SENTINEL")
                return real_link(src, dst)

            collect.os.link = racing_link
            try:
                written = collect.write_snapshot_file(snap, tmp)
                with self.assertRaises(FileExistsError):
                    collect.write_snapshot_file(snap, tmp, filename=first.name)
            finally:
                collect.os.link = real_link
            self.assertEqual(first.read_text(), "SENTINEL")
            self.assertEqual(written.name, "snapshot-20261019T000000Z-2.json")
            self.assertEqual(json.loads(written.read_text())["started_at"], snap["started_at"])
            self.assertEqual([p.name for p in Path(tmp).iterdir() if p.name.startswith(".tmp-")], [])


if __name__ == "__main__":
    unittest.main()
