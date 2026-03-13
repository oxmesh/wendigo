#!/usr/bin/env python3
"""
Wendigo — crash triage tool

Usage:
  wendigo triage FILE              # single crash log
  wendigo triage -d DIR            # batch directory
  wendigo run BINARY [ARGS] -- CRASH   # reproduce + triage
  wendigo run BINARY [ARGS] -- -d DIR  # batch reproduce
  wendigo afl DIR                  # AFL++ aware triage
  wendigo info FILE                # quick one-liner summary
  wendigo diff CRASH1 CRASH2       # compare two crashes
  wendigo watch DIR --binary BIN   # monitor for new crashes

  wendigo --binary ./bsdtar --args "tf @@" --crash crash_file
  wendigo --log crash_asan.txt
  wendigo --binary ./bsdtar --args "tf @@" --crash-dir /tmp/fuzz/crashes/
  --html report.html   Write standalone HTML report
  --json               Print JSONL to stdout
  -q / --quiet         Suppress everything except results
  -v / --verbose       Detailed reproduction output
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from core.parser import parse_asan_log
from core.analyzer import analyze
from core.visualizer import generate_visualization
from core.root_cause import analyze_root_cause
from core.cwe import get_cwe, get_exploitation_hints
SEVERITY_COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[0;31m",
    "MEDIUM": "\033[0;33m",
    "LOW": "\033[0;36m",
    "NOT EXPLOITABLE": "\033[0;32m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
MAGENTA = "\033[0;35m"
CYAN = "\033[0;36m"
WHITE = "\033[1;37m"
BRED = "\033[1;31m"
# ──────────────────────────────────────────────────────────────
# Utility: controlled output — when --json, non-JSON goes to stderr
# ──────────────────────────────────────────────────────────────

class OutputController:
    """Controls where output goes based on --json, --quiet, --verbose flags."""
    def __init__(self, json_mode=False, quiet=False, verbose=False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose

    def status(self, msg, **kwargs):
        """Print status/progress to stderr (or suppress if quiet)."""
        if self.quiet:
            return
        print(msg, file=sys.stderr, **kwargs)

    def warn(self, msg):
        """Print warning to stderr."""
        print(msg, file=sys.stderr)

    def result_json(self, data):
        """Print a JSON line to stdout."""
        print(json.dumps(data, separators=(',', ':')), flush=True)

    def verbose_msg(self, msg):
        """Print verbose info to stderr."""
        if self.verbose:
            print(msg, file=sys.stderr)
out = OutputController()
def main():
    # Check for subcommand-style usage
    if len(sys.argv) > 1 and sys.argv[1] in ("triage", "run", "afl", "info", "diff", "watch"):
        return _subcommand_dispatch()

    # Legacy CLI
    p = argparse.ArgumentParser(
        description="Wendigo — crash triage tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Subcommands: triage, run, afl, info, diff, watch (use 'wendigo <cmd> -h' for help)",
    )
    p.add_argument("--binary", "-b", help="Path to ASAN-instrumented binary")
    p.add_argument("--args", type=str, default="@@",
                    help="Arguments to binary as a string. Use @@ for crash file path.")
    p.add_argument("--crash", "-c", help="Path to a single crash file")
    p.add_argument("--crash-dir", "-d", help="Path to directory of crash files (batch mode)")
    p.add_argument("--log", "-l", help="Path to existing ASAN/KASAN log (skip reproduction)")
    p.add_argument("--afl-dir", help="Path to AFL++ output directory (auto-detect crashes, binary, stats)")
    p.add_argument("--stdin", action="store_true", help="Feed crash via stdin instead of @@")
    p.add_argument("--timeout", type=int, default=30, help="Reproduction timeout in seconds")
    p.add_argument("--source-dir", "-s", help="Source directory to resolve file paths from ASAN traces")
    p.add_argument("--html", "-o", default=None, help="Output HTML path (default: wendigo_report.html)")
    p.add_argument("--json", action="store_true", help="Output JSONL to stdout (one JSON object per crash)")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress CLI output")
    p.add_argument("--verbose", "-v", action="store_true", help="Detailed reproduction output")
    p.add_argument("--stdin-log", action="store_true", help="Read ASAN log from stdin (for piping)")

    args = p.parse_args()

    global out
    out = OutputController(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)

    # AFL++ dir mode
    if args.afl_dir:
        return _handle_afl_dir(args.afl_dir, args)

    if not args.log and not args.binary and not args.stdin_log:
        p.error("Need --binary (+ --crash), --log, --afl-dir, or --stdin-log")
    if args.binary and not args.crash and not args.crash_dir and not args.log:
        p.error("Need --crash, --crash-dir, or --log with --binary")

    # Stdin log mode (piping)
    if args.stdin_log:
        log_text = sys.stdin.read()
        if not log_text.strip():
            out.warn("[!] No input received on stdin")
            sys.exit(1)
        result = _triage(log_text, source="<stdin>", source_dir=args.source_dir)
        if result:
            _output(result, args, default_name="wendigo_report.html")
        else:
            out.warn("[!] Could not parse ASAN log from stdin")
            sys.exit(1)
        return

    # Single ASAN log mode
    if args.log:
        log_path = Path(args.log)
        if not log_path.is_file():
            out.warn(f"[!] File not found: {args.log}")
            sys.exit(1)
        try:
            log_text = log_path.read_text(errors="replace")
        except Exception as e:
            out.warn(f"[!] Cannot read {args.log}: {e}")
            sys.exit(1)
        result = _triage(log_text, source=args.log, source_dir=args.source_dir)
        if result:
            _output(result, args, default_name="wendigo_report.html")
        else:
            out.warn(f"[!] Could not parse ASAN log from: {args.log}")
            sys.exit(1)
        return

    # Single crash mode
    if args.crash:
        if not args.binary:
            out.warn("[!] Need --binary (-b) to reproduce crashes. Or use --log if you have ASAN output.")
            sys.exit(1)
        if not Path(args.binary).exists():
            out.warn(f"[!] Binary not found: {args.binary}")
            sys.exit(1)
        if not Path(args.crash).exists():
            out.warn(f"[!] Crash file not found: {args.crash}")
            sys.exit(1)
        result = _reproduce_and_triage(args.binary, args.crash, args.args, args.stdin, args.timeout, source_dir=args.source_dir)
        if result:
            _output(result, args, default_name=_report_name(args.crash))
        return

    # Batch mode
    if args.crash_dir:
        _handle_batch(args.binary, args.crash_dir, args)
        return
# ──────────────────────────────────────────────────────────────
# Subcommand dispatch
# ──────────────────────────────────────────────────────────────

def _subcommand_dispatch():
    cmd = sys.argv[1]
    argv = sys.argv[2:]

    if cmd == "triage":
        return _cmd_triage(argv)
    elif cmd == "run":
        return _cmd_run(argv)
    elif cmd == "afl":
        return _cmd_afl(argv)
    elif cmd == "info":
        return _cmd_info(argv)
    elif cmd == "diff":
        return _cmd_diff(argv)
    elif cmd == "watch":
        return _cmd_watch(argv)
def _add_common_args(p):
    """Add common output args to a subcommand parser."""
    p.add_argument("--html", "-o", default=None, help="Output HTML path")
    p.add_argument("--json", action="store_true", help="Output JSONL to stdout")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress CLI output")
    p.add_argument("--verbose", "-v", action="store_true", help="Detailed output")
    p.add_argument("--source-dir", "-s", help="Source directory for traces")
    p.add_argument("--workers", type=int, default=None, help="Number of parallel workers for batch mode")
    p.add_argument("--dedup-only", action="store_true", help="Only group duplicates without full triage")
def _cmd_triage(argv):
    p = argparse.ArgumentParser(prog="wendigo triage", description="Triage crash log(s)")
    p.add_argument("file", nargs="?", help="Crash log file")
    p.add_argument("-d", "--dir", help="Directory of crash logs (batch)")
    _add_common_args(p)
    args = p.parse_args(argv)

    global out
    out = OutputController(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)

    if args.dir:
        # Batch triage of log files
        crash_dir = Path(args.dir)
        files = sorted([f for f in crash_dir.iterdir() if f.is_file() and not f.name.startswith(".")])
        if not files:
            out.warn(f"[!] No files found in {crash_dir}")
            sys.exit(1)
        _handle_batch_logs(files, args)
    elif args.file:
        log_path = Path(args.file)
        if not log_path.is_file():
            out.warn(f"[!] File not found: {args.file}")
            sys.exit(1)
        log_text = log_path.read_text(errors="replace")
        result = _triage(log_text, source=args.file, source_dir=args.source_dir)
        if result:
            _output(result, args, default_name="wendigo_report.html")
        else:
            out.warn(f"[!] Could not parse crash log: {args.file}")
            sys.exit(1)
    else:
        p.error("Need FILE or -d DIR")
def _cmd_run(argv):
    p = argparse.ArgumentParser(prog="wendigo run", description="Reproduce crash and triage")
    p.add_argument("binary", help="Path to ASAN-instrumented binary")
    p.add_argument("args", nargs="*", help="Binary arguments (use @@ for crash path)")
    p.add_argument("-d", "--dir", help="Directory of crash files (batch)")
    p.add_argument("--crash", "-c", help="Single crash file")
    p.add_argument("--stdin", action="store_true", help="Feed crash via stdin")
    p.add_argument("--timeout", type=int, default=30, help="Reproduction timeout")
    _add_common_args(p)

    # Handle -- separator for crash file
    if "--" in argv:
        idx = argv.index("--")
        pre = argv[:idx]
        post = argv[idx+1:]
        args = p.parse_args(pre)
        if post and post[0] == "-d" and len(post) > 1:
            args.dir = post[1]
        elif post:
            args.crash = post[0]
    else:
        args = p.parse_args(argv)

    global out
    out = OutputController(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)

    extra_args = " ".join(args.args) if args.args else "@@"

    if args.dir:
        args.binary_path = args.binary
        args.args_str = extra_args
        _handle_batch(args.binary, args.dir, args, extra_args=extra_args)
    elif args.crash:
        result = _reproduce_and_triage(args.binary, args.crash, extra_args, args.stdin, args.timeout, source_dir=args.source_dir)
        if result:
            _output(result, args, default_name=_report_name(args.crash))
    else:
        p.error("Need --crash or -d DIR (or use -- CRASH)")
def _cmd_afl(argv):
    p = argparse.ArgumentParser(prog="wendigo afl", description="AFL++ aware triage")
    p.add_argument("dir", help="AFL++ output directory")
    p.add_argument("--timeout", type=int, default=30, help="Reproduction timeout")
    _add_common_args(p)
    args = p.parse_args(argv)

    global out
    out = OutputController(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)

    _handle_afl_dir(args.dir, args)
def _cmd_info(argv):
    p = argparse.ArgumentParser(prog="wendigo info", description="Quick one-liner crash summary")
    p.add_argument("file", help="Crash log file")
    p.add_argument("--source-dir", "-s", help="Source directory")
    args = p.parse_args(argv)

    log_text = Path(args.file).read_text(errors="replace")
    result = _triage(log_text, source=args.file, source_dir=args.source_dir)
    if not result:
        print(f"UNKNOWN | Could not parse: {args.file}", file=sys.stderr)
        sys.exit(1)

    report = result["report"]
    analysis = result["analysis"]
    sev = analysis["severity"]
    bt = report.bug_type
    at = report.access_type
    sz = report.access_size
    func = report.crash_trace[0].function if report.crash_trace else "?"
    loc = ""
    if report.crash_trace and report.crash_trace[0].source_file:
        f = report.crash_trace[0]
        loc = f"{Path(f.source_file).name}:{f.line}"
    elif report.crash_trace and report.crash_trace[0].function:
        loc = func
    cid = result["crash_id"]

    print(f"{sev} | {bt} {at} {sz}B | {func} ({loc}) | crash_id: {cid}")
def _cmd_diff(argv):
    p = argparse.ArgumentParser(prog="wendigo diff", description="Compare two crashes")
    p.add_argument("crash1", help="First crash log")
    p.add_argument("crash2", help="Second crash log")
    p.add_argument("--html", "-o", help="Output HTML diff")
    p.add_argument("--source-dir", "-s", help="Source directory")
    args = p.parse_args(argv)

    log1 = Path(args.crash1).read_text(errors="replace")
    log2 = Path(args.crash2).read_text(errors="replace")
    r1 = _triage(log1, source=args.crash1, source_dir=args.source_dir)
    r2 = _triage(log2, source=args.crash2, source_dir=args.source_dir)

    if not r1:
        print(f"[!] Could not parse: {args.crash1}", file=sys.stderr)
        sys.exit(1)
    if not r2:
        print(f"[!] Could not parse: {args.crash2}", file=sys.stderr)
        sys.exit(1)

    _print_diff(r1, r2, args)
def _cmd_watch(argv):
    p = argparse.ArgumentParser(prog="wendigo watch", description="Monitor directory for new crashes")
    p.add_argument("dir", help="Directory to watch")
    p.add_argument("--binary", "-b", required=True, help="ASAN-instrumented binary")
    p.add_argument("--args", type=str, default="@@", help="Binary arguments")
    p.add_argument("--timeout", type=int, default=30, help="Reproduction timeout")
    p.add_argument("--poll", type=int, default=5, help="Poll interval in seconds (fallback)")
    p.add_argument("--source-dir", "-s", help="Source directory")
    p.add_argument("--json", action="store_true", help="Output JSONL")
    p.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    args = p.parse_args(argv)

    global out
    out = OutputController(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)

    _handle_watch(args)
# ──────────────────────────────────────────────────────────────
# AFL++ support
# ──────────────────────────────────────────────────────────────

def _parse_afl_stats(afl_dir):
    """Parse AFL++ fuzzer_stats and fuzzer_setup from an AFL output directory."""
    afl_dir = Path(afl_dir)
    info = {"binary": None, "args": None, "stats": {}, "crash_dirs": []}

    # Find fuzzer_setup (contains command line)
    for candidate in [afl_dir / "fuzzer_setup", afl_dir / "default" / "fuzzer_setup"]:
        if candidate.is_file():
            text = candidate.read_text(errors="replace")
            # AFL++ fuzzer_setup has two formats:
            # 1. "command_line : afl-fuzz ... -- /path/binary args"
            # 2. "# command line:\n'afl-fuzz' '-i' ... '--' '/path/binary' 'arg1' '@@'"
            m = re.search(r"command_line\s*:\s*(.+)", text)
            if m:
                raw = m.group(1).strip()
            else:
                # Try multi-line format with quoted args
                lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith('#')]
                raw = " ".join(lines)
            # Strip quotes from each token
            parts = [p.strip("'\"") for p in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", raw)]
            # Find binary (after -- in afl-fuzz command)
            if "--" in parts:
                idx = parts.index("--")
                if idx + 1 < len(parts):
                    info["binary"] = parts[idx + 1]
                    info["args"] = " ".join(parts[idx + 2:]) if idx + 2 < len(parts) else "@@"
            break

    # Find fuzzer_stats
    for candidate in [afl_dir / "fuzzer_stats", afl_dir / "default" / "fuzzer_stats"]:
        if candidate.is_file():
            for line in candidate.read_text(errors="replace").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info["stats"][k.strip()] = v.strip()
            break

    # Find crash directories
    skip_files = {"README.txt", ".state"}
    for candidate in [
        afl_dir / "default" / "crashes",
        afl_dir / "crashes",
    ]:
        if candidate.is_dir():
            crashes = sorted([
                f for f in candidate.iterdir()
                if f.is_file() and f.name not in skip_files and not f.name.startswith(".")
            ])
            if crashes:
                info["crash_dirs"].append({"path": candidate, "files": crashes})

    # Also check for multiple fuzzers (e.g., main, secondary)
    for subdir in sorted(afl_dir.iterdir()) if afl_dir.is_dir() else []:
        if subdir.is_dir() and subdir.name != "default":
            crash_dir = subdir / "crashes"
            if crash_dir.is_dir():
                crashes = sorted([
                    f for f in crash_dir.iterdir()
                    if f.is_file() and f.name not in skip_files and not f.name.startswith(".")
                ])
                if crashes:
                    info["crash_dirs"].append({"path": crash_dir, "files": crashes})

    return info
def _handle_afl_dir(afl_dir_path, args):
    """Handle AFL++ directory triage."""
    info = _parse_afl_stats(afl_dir_path)

    binary = getattr(args, 'binary', None) or info["binary"]
    extra_args = getattr(args, 'args', None) or info["args"] or "@@"
    timeout = getattr(args, 'timeout', 30)

    if not binary:
        out.warn("[!] Could not detect binary from AFL++ directory. Use --binary.")
        sys.exit(1)

    all_crashes = []
    for cd in info["crash_dirs"]:
        all_crashes.extend(cd["files"])

    if not all_crashes:
        out.warn(f"[!] No crash files found in AFL++ directory: {afl_dir_path}")
        sys.exit(1)

    # Print AFL++ stats header
    stats = info["stats"]
    if stats and not out.quiet:
        out.status(f"\n  {WHITE}👁  Wendigo{RESET} {DIM}— AFL++ Triage{RESET}\n")
        out.status(f"  {CYAN}📂 AFL++ dir:{RESET} {WHITE}{afl_dir_path}{RESET}")
        out.status(f"  {DIM}   Binary: {binary}{RESET}")
        if "execs_done" in stats:
            out.status(f"  {DIM}   Total execs: {stats['execs_done']}{RESET}")
        if "execs_per_sec" in stats:
            out.status(f"  {DIM}   Speed: {stats['execs_per_sec']} exec/s{RESET}")
        if "run_time" in stats:
            out.status(f"  {DIM}   Runtime: {stats['run_time']}s{RESET}")
        out.status(f"  {CYAN}💥 Found {WHITE}{len(all_crashes)}{RESET} crash files\n")

    # Now do batch triage
    _handle_batch_crashes(binary, all_crashes, args, extra_args=extra_args, timeout=timeout,
                          afl_stats=stats)
# ──────────────────────────────────────────────────────────────
# Batch processing
# ──────────────────────────────────────────────────────────────

def _handle_batch(binary, crash_dir_path, args, extra_args=None):
    """Handle batch crash reproduction + triage."""
    crash_dir = Path(crash_dir_path)
    crashes = sorted([f for f in crash_dir.iterdir() if f.is_file() and not f.name.startswith(".")])
    if not crashes:
        out.warn(f"[!] No crash files found in {crash_dir}")
        sys.exit(1)

    ea = extra_args or getattr(args, 'args', "@@")
    timeout = getattr(args, 'timeout', 30)
    _handle_batch_crashes(binary, crashes, args, extra_args=ea, timeout=timeout)
def _handle_batch_logs(files, args):
    """Handle batch triage of existing log files."""
    out.status(f"\n  {WHITE}👁  Wendigo{RESET} {DIM}— Batch Log Triage{RESET}\n")
    out.status(f"  {CYAN}📂 Found {WHITE}{len(files)}{RESET} log files\n")

    out_dir = Path(args.html) if args.html else Path("wendigo_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    generate_html = not args.json or args.html
    if generate_html:
        _copy_static_assets(out_dir)

    results = []
    no_reproduce = 0
    for i, f in enumerate(files):
        _print_progress(i, len(files), f.name)
        log_text = f.read_text(errors="replace")
        result = _triage(log_text, source=str(f), source_dir=args.source_dir)
        if result:
            results.append(result)
            if args.json:
                out.result_json(_result_to_jsonl(result))
            if generate_html:
                html_path = out_dir / f"{_safe_name(f.name)}.html"
                html_path.write_text(_generate_html(result, external_assets=True))
        else:
            no_reproduce += 1
            out.warn(f"[WARN] {f.name}: could not parse crash log")
            if args.json:
                out.result_json({"file": str(f), "status": "parse_error"})

    _print_progress_done(len(files))
    _print_summary_card(results, len(files), no_reproduce, 0, 0, out_dir if generate_html else None)
def _handle_batch_crashes(binary, crashes, args, extra_args="@@", timeout=30, afl_stats=None):
    """Core batch processing for crash reproduction + triage."""
    use_stdin = getattr(args, 'stdin', False)
    source_dir = getattr(args, 'source_dir', None)
    workers = getattr(args, 'workers', None) or max(1, (os.cpu_count() or 2) // 2)
    dedup_only = getattr(args, 'dedup_only', False)

    out.status(f"\n  {WHITE}👁  Wendigo{RESET} {DIM}— Batch Triage{RESET}\n")
    out.status(f"  {CYAN}📂 Found {WHITE}{len(crashes)}{RESET} crash files")
    out.status(f"  {DIM}   Binary: {binary}{RESET}")
    out.status(f"  {DIM}   Source: {source_dir or 'N/A'}{RESET}")
    out.status(f"  {DIM}   Workers: {workers}{RESET}\n")

    # Quick content dedup
    hash_groups = {}
    for crash in crashes:
        try:
            h = hashlib.sha256(Path(crash).read_bytes()).hexdigest()[:16]
        except Exception:
            h = str(crash)
        hash_groups.setdefault(h, []).append(crash)

    unique_by_content = [files[0] for files in hash_groups.values()]
    content_dupes = len(crashes) - len(unique_by_content)
    if content_dupes > 0:
        out.status(f"  {MAGENTA}🔗 Content dedup: {WHITE}{len(unique_by_content)}{RESET} unique {DIM}({content_dupes} identical files skipped){RESET}\n")

    if dedup_only:
        out.status(f"  {GREEN}Dedup complete.{RESET} {len(crashes)} crashes → {len(unique_by_content)} unique by content hash\n")
        return

    out_dir = Path(args.html) if args.html else Path("wendigo_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    generate_html = not args.json or args.html
    if generate_html:
        _copy_static_assets(out_dir)

    results = []
    no_reproduce = 0
    sev_counts = Counter()
    lock = threading.Lock()
    start_time = time.monotonic()

    def _process_one(crash):
        return _reproduce_and_triage(binary, str(crash), extra_args, use_stdin, timeout, quiet=True, source_dir=source_dir)

    crashes_to_process = unique_by_content

    if workers > 1 and len(crashes_to_process) > 1:
        # Parallel processing
        with concurrent.futures.ProcessPoolExecutor(max_workers=min(workers, len(crashes_to_process))) as executor:
            futures = {}
            for crash in crashes_to_process:
                fut = executor.submit(_reproduce_and_triage_standalone,
                                      binary, str(crash), extra_args, use_stdin, timeout, source_dir)
                futures[fut] = crash

            done_count = 0
            for fut in concurrent.futures.as_completed(futures):
                crash = futures[fut]
                done_count += 1
                try:
                    result = fut.result()
                except Exception:
                    result = None

                if result:
                    with lock:
                        results.append(result)
                        sev = result["analysis"]["severity"]
                        sev_counts[sev] += 1
                    if args.json:
                        out.result_json(_result_to_jsonl(result))
                    if generate_html:
                        html_path = out_dir / f"{_safe_name(Path(crash).name)}.html"
                        html_path.write_text(_generate_html(result, external_assets=True))
                else:
                    with lock:
                        no_reproduce += 1
                    if args.json:
                        out.result_json({"file": str(crash), "status": "no_reproduce"})

                _print_progress_bar(done_count, len(crashes_to_process), sev_counts, start_time)
    else:
        # Sequential processing
        for i, crash in enumerate(crashes_to_process):
            result = _reproduce_and_triage(binary, str(crash), extra_args, use_stdin, timeout, quiet=True, source_dir=source_dir)
            if result:
                results.append(result)
                sev = result["analysis"]["severity"]
                sev_counts[sev] += 1
                if args.json:
                    out.result_json(_result_to_jsonl(result))
                if generate_html:
                    html_path = out_dir / f"{_safe_name(Path(crash).name)}.html"
                    html_path.write_text(_generate_html(result, external_assets=True))
            else:
                no_reproduce += 1
                if args.json:
                    out.result_json({"file": str(crash), "status": "no_reproduce"})

            _print_progress_bar(i + 1, len(crashes_to_process), sev_counts, start_time)

    _print_progress_done(len(crashes_to_process))

    # ASAN output dedup (same top 3 frames)
    asan_dupes = 0
    seen_ids = {}
    for r in results:
        cid = r.get("crash_id", "")
        if cid in seen_ids:
            asan_dupes += 1
        else:
            seen_ids[cid] = r

    _print_summary_card(results, len(crashes), no_reproduce, content_dupes, asan_dupes,
                        out_dir if generate_html else None, afl_stats=afl_stats)
def _reproduce_and_triage_standalone(binary, crash_path, extra_args, use_stdin, timeout, source_dir):
    """Standalone version for multiprocessing."""
    return _reproduce_and_triage(binary, crash_path, extra_args, use_stdin, timeout, quiet=True, source_dir=source_dir)
def _print_progress(i, total, name):
    """Print progress bar to stderr."""
    if out.quiet:
        return
    progress = f"{i+1}/{total}"
    bar_filled = int((i+1) / total * 20)
    bar = f"{GREEN}{'█' * bar_filled}{DIM}{'░' * (20 - bar_filled)}{RESET}"
    print(f"\r  {bar} {WHITE}{progress}{RESET} {DIM}{name[:45]}{RESET}    ", end="", file=sys.stderr)
def _print_progress_bar(done, total, sev_counts, start_time):
    """Print rich progress bar with severity counts and ETA."""
    if out.quiet:
        return
    bar_w = 20
    filled = int(done / max(total, 1) * bar_w)
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (bar_w - filled)}{RESET}"

    elapsed = time.monotonic() - start_time
    eta = ""
    if done > 0 and done < total:
        remaining = (elapsed / done) * (total - done)
        if remaining < 60:
            eta = f"ETA: {int(remaining)}s"
        else:
            eta = f"ETA: {int(remaining/60)}m{int(remaining%60)}s"

    parts = [f"{bar} {WHITE}{done}/{total}{RESET}"]
    for sev, label in [("CRITICAL", "CRIT"), ("HIGH", "HIGH"), ("MEDIUM", "MED"), ("LOW", "LOW")]:
        c = sev_counts.get(sev, 0)
        if c > 0:
            color = BRED if sev == "CRITICAL" else RED if sev == "HIGH" else YELLOW if sev == "MEDIUM" else CYAN
            parts.append(f"{color}{c} {label}{RESET}")
    if eta:
        parts.append(f"{DIM}{eta}{RESET}")

    line = " | ".join(parts)
    print(f"\r  {line}    ", end="", file=sys.stderr)
def _print_progress_done(total):
    """Print progress completion to stderr."""
    if out.quiet:
        return
    print(f"\r  {GREEN}{'█' * 20}{RESET} {WHITE}{total}/{total}{RESET} Done!                                                  ", file=sys.stderr)
    print(file=sys.stderr)
def _print_summary_card(results, total, no_reproduce, content_dupes, asan_dupes, out_dir, afl_stats=None):
    """Print a nice summary card box to stderr."""
    sev_counts = Counter(r["analysis"]["severity"] for r in results)
    unique_ids = set(r.get("crash_id", id(r)) for r in results)
    triaged = len(results)
    unique = len(unique_ids)

    if not out.quiet:
        w = 50
        out.status(f"  ┌{'─' * w}┐")
        out.status(f"  │{WHITE}  Wendigo Batch Summary{RESET}{' ' * (w - 22)}│")
        out.status(f"  │{' ' * w}│")
        total_line = f"  Total: {total} crashes ({unique} unique)"
        out.status(f"  │{total_line}{' ' * (w - len(total_line) + 2)}│")

        sev_parts = []
        for sev, color in [("CRITICAL", BRED), ("HIGH", RED), ("MEDIUM", YELLOW), ("LOW", CYAN), ("NOT EXPLOITABLE", GREEN)]:
            c = sev_counts.get(sev, 0)
            if c > 0:
                sev_parts.append(f"{color}{sev}: {c}{RESET}")
        if sev_parts:
            # Print severity line(s) — fit within box
            sev_str = "  " + "  ".join(sev_parts)
            out.status(f"  │{sev_str}{' ' * max(0, w - len('  ' + '  '.join(f'{s}: {sev_counts.get(s, 0)}' for s in ['CRITICAL','HIGH','MEDIUM','LOW','NOT EXPLOITABLE'] if sev_counts.get(s, 0))))}│")

        if no_reproduce > 0:
            fail_line = f"  Failed: {no_reproduce}"
            out.status(f"  │{YELLOW}{fail_line}{RESET}{' ' * (w - len(fail_line))}│")

        if out_dir:
            _generate_index(results, out_dir, afl_stats=afl_stats)
            abs_index = str((out_dir / "index.html").resolve())
            rpt_line = f"  Reports: {abs_index}"
            if len(rpt_line) > w:
                rpt_line = f"  Reports: ./{out_dir}/index.html"
            out.status(f"  │{GREEN}{rpt_line[:w]}{RESET}{' ' * max(0, w - len(rpt_line[:w]))}│")

        out.status(f"  └{'─' * w}┘")
        out.status("")

        if out_dir:
            _print_open_command(str((out_dir / "index.html").resolve()))
            out.status("")
# ──────────────────────────────────────────────────────────────
# Crash diffing
# ──────────────────────────────────────────────────────────────

def _print_diff(r1, r2, args):
    """Print a side-by-side diff of two crash results."""
    rep1, rep2 = r1["report"], r2["report"]
    ana1, ana2 = r1["analysis"], r2["analysis"]

    name1 = Path(r1["source"]).name
    name2 = Path(r2["source"]).name

    same_type = rep1.bug_type == rep2.bug_type
    same_func = False
    func1 = rep1.crash_trace[0].function if rep1.crash_trace else "?"
    func2 = rep2.crash_trace[0].function if rep2.crash_trace else "?"
    same_func = func1 == func2
    same_id = r1["crash_id"] == r2["crash_id"]

    print(f"\n  {WHITE}👁  Wendigo{RESET} {DIM}— Crash Diff{RESET}\n")
    print(f"  {DIM}{'─'*62}{RESET}")
    print(f"  {'':30s}  {CYAN}{name1[:28]:28s}{RESET}  {MAGENTA}{name2[:28]:28s}{RESET}")
    print(f"  {DIM}{'─'*62}{RESET}")

    def _row(label, v1, v2, same=None):
        if same is None:
            same = v1 == v2
        marker = f"{GREEN}={RESET}" if same else f"{RED}≠{RESET}"
        print(f"  {DIM}{label:14s}{RESET} {marker} {v1:28s}  {v2:28s}")

    _row("Bug Type", rep1.bug_type, rep2.bug_type, same_type)
    _row("Severity", ana1["severity"], ana2["severity"])
    _row("Score", str(ana1["score"]), str(ana2["score"]))
    _row("Access", f"{rep1.access_type} {rep1.access_size}B", f"{rep2.access_type} {rep2.access_size}B")
    _row("Function", func1, func2, same_func)
    _row("Crash ID", r1["crash_id"], r2["crash_id"], same_id)

    # Stack frame diff
    print(f"\n  {BLUE}Stack Trace Diff:{RESET}")
    frames1 = [(f.function or "??") for f in (rep1.crash_trace or [])[:10]]
    frames2 = [(f.function or "??") for f in (rep2.crash_trace or [])[:10]]

    max_frames = max(len(frames1), len(frames2))
    for i in range(max_frames):
        f1 = frames1[i] if i < len(frames1) else ""
        f2 = frames2[i] if i < len(frames2) else ""
        if f1 == f2:
            print(f"    {GREEN}={RESET} #{i} {f1}")
        else:
            print(f"    {RED}≠{RESET} #{i} {CYAN}{f1:30s}{RESET} {MAGENTA}{f2}{RESET}")

    print(f"\n  {DIM}{'─'*62}{RESET}")
    verdict = f"{GREEN}LIKELY DUPLICATE{RESET}" if same_id else (
        f"{YELLOW}SAME TYPE/LOCATION{RESET}" if same_type and same_func else f"{RED}DIFFERENT BUGS{RESET}"
    )
    print(f"  Verdict: {verdict}")

    if same_id:
        print(f"  {DIM}Same crash_id — these are the same bug{RESET}")
    print()

    # HTML diff
    if args.html:
        _generate_diff_html(r1, r2, args.html)
        print(f"  {GREEN}📄 Diff report:{RESET} {WHITE}{Path(args.html).resolve()}{RESET}\n")
def _generate_diff_html(r1, r2, html_path):
    """Generate an HTML diff report."""
    rep1, rep2 = r1["report"], r2["report"]
    ana1, ana2 = r1["analysis"], r2["analysis"]
    name1 = Path(r1["source"]).name
    name2 = Path(r2["source"]).name

    same_id = r1["crash_id"] == r2["crash_id"]
    same_type = rep1.bug_type == rep2.bug_type

    def _diff_class(a, b):
        return "diff-same" if a == b else "diff-different"

    frames1 = [(f.function or "??") for f in (rep1.crash_trace or [])[:10]]
    frames2 = [(f.function or "??") for f in (rep2.crash_trace or [])[:10]]

    trace_html = ""
    for i in range(max(len(frames1), len(frames2))):
        f1 = frames1[i] if i < len(frames1) else ""
        f2 = frames2[i] if i < len(frames2) else ""
        cls = "diff-same" if f1 == f2 else "diff-different"
        trace_html += f'<tr class="{cls}"><td>#{i}</td><td>{_esc(f1)}</td><td>{_esc(f2)}</td></tr>\n'

    html = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Wendigo Diff — {_esc(name1)} vs {_esc(name2)}</title>
<style>
body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, sans-serif; padding: 40px; }}
.container {{ max-width: 900px; margin: 0 auto; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 13px; }}
th {{ color: #8b949e; }}
.diff-same {{ background: rgba(56,139,66,0.1); }}
.diff-different {{ background: rgba(218,54,51,0.1); }}
h1 {{ color: #f0f6fc; }} h2 {{ color: #c9d1d9; margin-top: 24px; }}
.verdict {{ font-size: 18px; padding: 12px; border-radius: 8px; margin: 16px 0; }}
.verdict-dup {{ background: rgba(56,139,66,0.2); color: #3fb950; }}
.verdict-diff {{ background: rgba(218,54,51,0.2); color: #f85149; }}
</style></head><body><div class="container">
<h1>👁 Wendigo — Crash Diff</h1>
<div class="verdict {'verdict-dup' if same_id else 'verdict-diff'}">
{"LIKELY DUPLICATE — same crash_id" if same_id else ("SAME TYPE/LOCATION" if same_type else "DIFFERENT BUGS")}
</div>
<table><thead><tr><th>Field</th><th>{_esc(name1)}</th><th>{_esc(name2)}</th></tr></thead><tbody>
<tr class="{_diff_class(rep1.bug_type, rep2.bug_type)}"><td>Bug Type</td><td>{rep1.bug_type}</td><td>{rep2.bug_type}</td></tr>
<tr class="{_diff_class(ana1['severity'], ana2['severity'])}"><td>Severity</td><td>{ana1['severity']}</td><td>{ana2['severity']}</td></tr>
<tr><td>Score</td><td>{ana1['score']}</td><td>{ana2['score']}</td></tr>
<tr class="{_diff_class(rep1.access_type, rep2.access_type)}"><td>Access</td><td>{rep1.access_type} {rep1.access_size}B</td><td>{rep2.access_type} {rep2.access_size}B</td></tr>
<tr class="{_diff_class(r1['crash_id'], r2['crash_id'])}"><td>Crash ID</td><td>{r1['crash_id']}</td><td>{r2['crash_id']}</td></tr>
</tbody></table>
<h2>Stack Trace Diff</h2>
<table><thead><tr><th>#</th><th>{_esc(name1)}</th><th>{_esc(name2)}</th></tr></thead><tbody>{trace_html}</tbody></table>
</div></body></html>'''

    Path(html_path).write_text(html)
# ──────────────────────────────────────────────────────────────
# Watch mode
# ──────────────────────────────────────────────────────────────

def _handle_watch(args):
    """Watch a directory for new crash files and auto-triage."""
    watch_dir = Path(args.dir)
    if not watch_dir.is_dir():
        out.warn(f"[!] Not a directory: {args.dir}")
        sys.exit(1)

    out.status(f"\n  {WHITE}👁  Wendigo{RESET} {DIM}— Watch Mode{RESET}\n")
    out.status(f"  {CYAN}📂 Watching:{RESET} {WHITE}{watch_dir.resolve()}{RESET}")
    out.status(f"  {DIM}   Binary: {args.binary}{RESET}")
    out.status(f"  {DIM}   Args: {args.args}{RESET}")
    out.status(f"  {DIM}   Press Ctrl+C to stop{RESET}\n")

    seen = set(f.name for f in watch_dir.iterdir() if f.is_file())
    skip_files = {"README.txt", ".state"}

    # Try inotifywait first
    use_inotify = False
    try:

        result = subprocess.run(["which", "inotifywait"], capture_output=True)
        if result.returncode == 0:
            use_inotify = True
    except Exception:
        pass

    if use_inotify:
        out.status(f"  {GREEN}Using inotifywait for efficient monitoring{RESET}\n")
        _watch_inotify(watch_dir, args, seen, skip_files)
    else:
        out.status(f"  {DIM}Polling every {args.poll}s (install inotify-tools for efficiency){RESET}\n")
        _watch_poll(watch_dir, args, seen, skip_files)
def _watch_poll(watch_dir, args, seen, skip_files):
    """Poll-based watch."""
    try:
        while True:
            current = set()
            for f in watch_dir.iterdir():
                if f.is_file() and f.name not in skip_files and not f.name.startswith("."):
                    current.add(f.name)

            new_files = current - seen
            for name in sorted(new_files):
                _watch_triage_file(watch_dir / name, args)

            seen.update(new_files)
            time.sleep(args.poll)
    except KeyboardInterrupt:
        out.status(f"\n  {DIM}Watch stopped.{RESET}\n")
def _watch_inotify(watch_dir, args, seen, skip_files):
    """inotifywait-based watch."""

    try:
        proc = subprocess.Popen(
            ["inotifywait", "-m", "-e", "close_write,moved_to", "--format", "%f", str(watch_dir)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        for line in proc.stdout:
            name = line.strip()
            if name in skip_files or name.startswith(".") or name in seen:
                continue
            seen.add(name)
            path = watch_dir / name
            if path.is_file():
                # Small delay to ensure file is fully written
                time.sleep(0.5)
                _watch_triage_file(path, args)
    except KeyboardInterrupt:
        proc.terminate()
        out.status(f"\n  {DIM}Watch stopped.{RESET}\n")
def _watch_triage_file(path, args):
    """Triage a single file during watch mode."""
    out.status(f"  {YELLOW}⚡ New crash:{RESET} {WHITE}{path.name}{RESET}")
    result = _reproduce_and_triage(
        args.binary, str(path), args.args, False, args.timeout,
        quiet=True, source_dir=args.source_dir,
    )
    if result:
        report = result["report"]
        analysis = result["analysis"]
        sev = analysis["severity"]
        sev_color = SEVERITY_COLORS.get(sev, "")
        func = report.crash_trace[0].function if report.crash_trace else "?"
        if args.json:
            out.result_json(_result_to_jsonl(result))
        else:
            out.status(f"    {sev_color}{sev}{RESET} | {report.bug_type} {report.access_type} {report.access_size}B | {func} | {result['crash_id']}")
    else:
        out.warn(f"    {DIM}[no reproduce]{RESET}")
# ──────────────────────────────────────────────────────────────
# Core triage functions
# ──────────────────────────────────────────────────────────────

def _reproduce_and_triage(binary, crash_path, extra_args, use_stdin, timeout, quiet=False, source_dir=None):
    """Reproduce a crash with ASAN and triage it."""
    crash_path = str(Path(crash_path).resolve())
    binary = str(Path(binary).resolve())

    if isinstance(extra_args, str):
        arg_list = shlex.split(extra_args)
    else:
        arg_list = list(extra_args or [])

    has_placeholder = "@@" in arg_list

    if not quiet:
        out.verbose_msg(f"[*] Reproducing: {Path(crash_path).name}")

    if has_placeholder:

        full_cmd = [binary]
        for a in arg_list:
            if a == "@@":
                full_cmd.append(crash_path)
            else:
                full_cmd.append(a)

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:print_legend=1:abort_on_error=1:halt_on_error=1"

        try:
            result = subprocess.run(full_cmd, capture_output=True, timeout=timeout, env=env)
            stderr = result.stderr.decode("utf-8", errors="replace")
            returncode = result.returncode
            out.verbose_msg(f"[*] Exit code: {returncode}, stderr length: {len(stderr)}")
        except subprocess.TimeoutExpired:
            stderr = "TIMEOUT"
            returncode = -1
    else:
        from core.reproducer import reproduce
        returncode, _, stderr = reproduce(
            binary, input_file=crash_path, stdin_input=use_stdin, timeout=timeout,
        )

    if "AddressSanitizer" not in stderr and "SEGV" not in stderr:
        sig = 0
        if returncode < 0:
            sig = -returncode
        elif returncode > 128:
            sig = returncode - 128
        out.warn(f"[WARN] {Path(crash_path).name}: no ASAN output detected (exit code {returncode}, signal {sig})")
        return None

    # Check binary security features
    bin_sec = None
    try:
        from core.checksec import check_binary_security
        bin_sec = check_binary_security(binary)
    except Exception:
        pass

    return _triage(stderr, source=crash_path, source_dir=source_dir, binary_security=bin_sec)
def _crash_id(report) -> str:
    """Generate a unique crash ID based on bug type + top 3 non-sanitizer frames."""
    parts = [report.bug_type or "unknown"]
    count = 0
    for frame in (report.crash_trace or []):
        func = frame.function or ""
        if func.startswith("__") or func in ("malloc", "free", "calloc", "realloc", "_start"):
            continue
        parts.append(f"{func}:{frame.line}")
        count += 1
        if count >= 3:
            break
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
    return h
def _triage(asan_log, source="", source_dir=None, binary_security=None):
    """Parse, analyze, visualize, root-cause."""
    report = parse_asan_log(asan_log)
    if not report.bug_type:
        out.warn(f"[!] Could not determine bug type from: {source}")
        return None

    result = analyze(report)

    # Apply binary security adjustments to score
    if binary_security:
        adjustments = binary_security.exploitability_adjustments(report.bug_type, report.access_type)
        for delta, reason in adjustments:
            result["score"] = max(0, min(100, result["score"] + delta))
            result["factors"].append(reason)
        # Recalculate severity from adjusted score
        score = result["score"]
        if score >= 75:
            result["severity"] = "CRITICAL"
        elif score >= 55:
            result["severity"] = "HIGH"
        elif score >= 35:
            result["severity"] = "MEDIUM"
        elif score >= 15:
            result["severity"] = "LOW"
        else:
            result["severity"] = "NOT EXPLOITABLE"

    viz = generate_visualization(report, result)
    rca = analyze_root_cause(report, source_dir=source_dir)
    cid = _crash_id(report)

    # CWE classification
    cwe = get_cwe(report.bug_type)

    # Exploitation hints
    hints = get_exploitation_hints(report.bug_type, report.access_type, binary_security)

    return {
        "source": str(source),
        "crash_id": cid,
        "report": report,
        "analysis": result,
        "visualization": viz,
        "root_cause": rca,
        "raw_log": asan_log,
        "cwe": cwe,
        "exploitation_hints": hints,
        "binary_security": binary_security,
    }
def _result_to_jsonl(result):
    """Convert a result to a compact JSONL dict."""
    report = result["report"]
    analysis = result["analysis"]
    func = report.crash_trace[0].function if report.crash_trace else None
    addr = hex(report.access_address) if report.access_address else None
    frames = [{"num": f.frame_num, "func": f.function, "addr": hex(f.address),
               "file": f.source_file, "line": f.line} for f in (report.crash_trace or [])[:15]]
    d = {
        "file": result["source"],
        "crash_id": result.get("crash_id", ""),
        "bug_type": report.bug_type,
        "severity": analysis["severity"],
        "score": analysis["score"],
        "access_type": report.access_type,
        "crash_function": func,
        "crash_address": addr,
        "frames": frames,
    }
    if result.get("cwe"):
        d["cwe"] = result["cwe"]
    if report.is_kasan:
        d["is_kasan"] = True
    if report.is_gdb:
        d["is_gdb"] = True
        d["registers"] = {k: hex(v) for k, v in report.registers.items()}
    if result.get("binary_security"):
        d["binary_security"] = result["binary_security"].to_dict()
    return d
def _output(result, args, default_name="wendigo_report.html"):
    """Output result to CLI + HTML/JSON."""
    report = result["report"]
    analysis = result["analysis"]

    if args.json:
        out.result_json(_result_to_jsonl(result))
        if not args.html:
            return

    html_path = Path(args.html or default_name)
    html = _generate_html(result)
    html_path.write_text(html)

    if not args.quiet and not args.json:
        _print_cli(report, analysis, result.get("root_cause"), html_path=str(html_path),
                   cwe=result.get("cwe"), binary_security=result.get("binary_security"),
                   exploitation_hints=result.get("exploitation_hints"))
def _print_cli(report, result, rca=None, html_path=None, cwe=None, binary_security=None, exploitation_hints=None):
    sev = result["severity"]
    sev_color = SEVERITY_COLORS.get(sev, "")

    print(file=sys.stderr)
    print(f"  {DIM}{'─'*62}{RESET}", file=sys.stderr)
    if report.is_kasan:
        print(f"  {WHITE}👁  Wendigo{RESET} {DIM}— Kernel crash (KASAN){RESET} {DIM}by Mesh{RESET}", file=sys.stderr)
    elif report.is_gdb:
        print(f"  {WHITE}👁  Wendigo{RESET} {DIM}— GDB crash analysis{RESET} {DIM}by Mesh{RESET}", file=sys.stderr)
    else:
        print(f"  {WHITE}👁  Wendigo{RESET} {DIM}by Mesh{RESET}", file=sys.stderr)
    print(f"  {DIM}{'─'*62}{RESET}", file=sys.stderr)
    print(file=sys.stderr)

    bt_color = RED if "overflow" in report.bug_type or "write" in report.access_type.lower() else YELLOW
    cwe_str = f" {DIM}({cwe['id']}){RESET}" if cwe else ""
    print(f"  {DIM}Bug Type{RESET}      {bt_color}{BOLD}{report.bug_type}{RESET}{cwe_str}", file=sys.stderr)

    acc_color = BRED if report.access_type == "WRITE" else YELLOW
    print(f"  {DIM}Access{RESET}        {acc_color}{report.access_type}{RESET} of {WHITE}{report.access_size}{RESET} bytes", file=sys.stderr)

    addr_str = hex(report.access_address) if report.access_address else 'N/A'
    print(f"  {DIM}Address{RESET}       {MAGENTA}{addr_str}{RESET}", file=sys.stderr)

    print(f"  {DIM}Severity{RESET}      {sev_color}{BOLD}{sev}{RESET} {DIM}(score: {result['score']}/100){RESET}", file=sys.stderr)

    print(f"  {DIM}Summary{RESET}       {WHITE}{result['one_liner']}{RESET}", file=sys.stderr)
    print(file=sys.stderr)

    if report.heap_info:
        hi = report.heap_info
        print(f"  {CYAN}┌─ Heap Info{RESET}", file=sys.stderr)
        print(f"  {CYAN}│{RESET}  Region:    {WHITE}{hi.region_size}{RESET}B, {hi.offset}B {hi.direction}", file=sys.stderr)
        if hi.alloc_trace:
            func = hi.alloc_trace[0].function
            print(f"  {CYAN}│{RESET}  Alloc:     {GREEN}{func}(){RESET}", file=sys.stderr)
        if hi.free_trace:
            func = hi.free_trace[0].function
            print(f"  {CYAN}│{RESET}  Freed:     {RED}{func}(){RESET}", file=sys.stderr)
        print(f"  {CYAN}└{'─'*40}{RESET}", file=sys.stderr)
        print(file=sys.stderr)

    if report.stack_info:
        si = report.stack_info
        print(f"  {CYAN}┌─ Stack Info{RESET}", file=sys.stderr)
        print(f"  {CYAN}│{RESET}  Variable:  {WHITE}{si.variable_name}{RESET} ({si.variable_size}B)", file=sys.stderr)
        print(f"  {CYAN}│{RESET}  Offset:    {si.offset}B {si.direction}", file=sys.stderr)
        print(f"  {CYAN}└{'─'*40}{RESET}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"  {YELLOW}Exploitability Factors:{RESET}", file=sys.stderr)
    for f in result["factors"]:
        if "write" in f.lower() or "corrupt" in f.lower():
            print(f"    {RED}⚡ {f}{RESET}", file=sys.stderr)
        elif "read" in f.lower() or "leak" in f.lower():
            print(f"    {YELLOW}⚡ {f}{RESET}", file=sys.stderr)
        else:
            print(f"    {DIM}⚡{RESET} {f}", file=sys.stderr)
    print(file=sys.stderr)

    if report.crash_trace:
        # GDB: show register state
        if report.is_gdb and report.registers:
            print(f"  {BLUE}Register State:{RESET}", file=sys.stderr)
            pattern_vals = {0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
                            0x4444444444444444, 0x4545454545454545, 0x4646464646464646}
            important_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
            for reg in important_regs:
                if reg in report.registers:
                    val = report.registers[reg]
                    hexval = f"0x{val:016x}"
                    if val in pattern_vals:
                        print(f"    {RED}{BOLD}{reg:6s}{RESET} {RED}{hexval}{RESET}  {RED}← CONTROLLED{RESET}", file=sys.stderr)
                    elif reg == "rip":
                        print(f"    {MAGENTA}{BOLD}{reg:6s}{RESET} {MAGENTA}{hexval}{RESET}  {MAGENTA}← crash here{RESET}", file=sys.stderr)
                    else:
                        print(f"    {DIM}{reg:6s}{RESET} {hexval}", file=sys.stderr)
            print(file=sys.stderr)

        print(f"  {BLUE}Crash Stack Trace:{RESET}", file=sys.stderr)
        for frame in report.crash_trace[:8]:
            num = f"{DIM}#{frame.frame_num}{RESET}"
            addr = f"{MAGENTA}{hex(frame.address)}{RESET}"
            func = frame.function or "??"
            if func.startswith("__") or func in ("malloc", "free", "calloc", "realloc"):
                func_colored = f"{DIM}{func}{RESET}"
            else:
                func_colored = f"{CYAN}{func}{RESET}"
            loc = ""
            if frame.source_file:
                loc = f" {DIM}{frame.source_file}:{frame.line}{RESET}"
            elif frame.module:
                loc = f" {DIM}({frame.module}){RESET}"
            print(f"    {num} {addr} in {func_colored}{loc}", file=sys.stderr)
        print(file=sys.stderr)

    if rca and rca.explanation:
        print(f"  {BRED}┌─ Root Cause Analysis{RESET}", file=sys.stderr)
        print(f"  {RED}│{RESET}  Pattern:    {WHITE}{rca.vulnerability_pattern}{RESET}", file=sys.stderr)
        if rca.root_cause_function:
            print(f"  {RED}│{RESET}  Function:   {CYAN}{rca.root_cause_function}(){RESET}", file=sys.stderr)
        if rca.root_cause_file:
            fname = Path(rca.root_cause_file).name
            print(f"  {RED}│{RESET}  Location:   {DIM}{fname}:{rca.root_cause_line}{RESET}", file=sys.stderr)
        print(f"  {RED}│{RESET}", file=sys.stderr)
        expl = rca.explanation
        while expl:
            chunk = expl[:70]
            if len(expl) > 70:
                idx = chunk.rfind(' ')
                if idx > 20:
                    chunk = expl[:idx]
                    expl = expl[idx+1:]
                else:
                    expl = expl[70:]
            else:
                expl = ""
            print(f"  {RED}│{RESET}  {chunk}", file=sys.stderr)
        print(f"  {RED}└{'─'*40}{RESET}", file=sys.stderr)

        if rca.suggestions:
            print(file=sys.stderr)
            print(f"  {GREEN}Suggestions:{RESET}", file=sys.stderr)
            for s in rca.suggestions:
                print(f"    {GREEN}→{RESET} {s}", file=sys.stderr)
        print(file=sys.stderr)

    # Binary security info
    if binary_security:
        print(f"  {CYAN}┌─ Target Hardening{RESET}", file=sys.stderr)
        print(f"  {CYAN}│{RESET}  {binary_security.format_line()}", file=sys.stderr)
        print(f"  {CYAN}└{'─'*40}{RESET}", file=sys.stderr)
        print(file=sys.stderr)

    # Exploitation hints
    if exploitation_hints:
        print(f"  {MAGENTA}Exploitation Notes:{RESET}", file=sys.stderr)
        for hint in exploitation_hints[:5]:
            print(f"    {MAGENTA}→{RESET} {hint}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"  {DIM}{'─'*62}{RESET}", file=sys.stderr)

    if html_path:
        abs_path = str(Path(html_path).resolve())
        print(f"\n  {GREEN}📄 Report:{RESET} {WHITE}{abs_path}{RESET}", file=sys.stderr)
        _print_open_command(abs_path)
    print(file=sys.stderr)
def _print_open_command(abs_path):
    """Print OS-appropriate open command."""
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or "microsoft" in os.uname().release.lower():
        try:

            win_path = subprocess.run(["wslpath", "-w", abs_path],
                                      capture_output=True, text=True, timeout=2).stdout.strip()
            if win_path:
                print(f"  {DIM}Open:{RESET} explorer.exe {win_path}", file=sys.stderr)
        except Exception:
            pass
    else:
        print(f"  {DIM}Open:{RESET} xdg-open {abs_path}", file=sys.stderr)
def _copy_static_assets(out_dir):
    """Copy CSS/JS to output directory for batch mode."""
    script_dir = Path(__file__).resolve().parent
    shutil.copy2(script_dir / "static" / "style.css", out_dir / "style.css")
    shutil.copy2(script_dir / "static" / "diagrams.js", out_dir / "diagrams.js")
# ──────────────────────────────────────────────────────────────
# HTML generation
# ──────────────────────────────────────────────────────────────

_cached_css = None
_cached_js = None

def _generate_html(result, external_assets=False):
    """Generate an HTML report."""
    global _cached_css, _cached_js
    script_dir = Path(__file__).resolve().parent
    if _cached_css is None:
        _cached_css = (script_dir / "static" / "style.css").read_text()
    if _cached_js is None:
        _cached_js = (script_dir / "static" / "diagrams.js").read_text()
    css = _cached_css
    js = _cached_js

    report = result["report"]
    analysis = result["analysis"]
    viz = result["visualization"]
    source = result["source"]

    data = json.dumps({
        "report": report.to_dict(),
        "analysis": analysis,
        "visualization": viz,
    }, separators=(',', ':'))

    sev = analysis["severity"]
    sev_class = sev.replace(" ", "-")

    # KASAN badge
    kasan_badge = ""
    if report.is_gdb:
        kasan_badge = '<span class="severity-badge" style="background:#e5a00d;color:#000;font-size:11px;padding:2px 8px;margin-left:8px">GDB</span>'
    elif report.is_kasan:
        kasan_badge = '<span class="severity-badge" style="background:var(--purple,#8957e5);font-size:11px;padding:2px 8px;margin-left:8px">KASAN</span>'

    # Stack trace — highlight attacker-controlled pattern addresses in red
    _pattern_addrs = {0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
                      0x4444444444444444, 0x4545454545454545, 0x4646464646464646,
                      0x4747474747474747, 0x4848484848484848,
                      0x41414141, 0x42424242, 0x43434343, 0x44444444}

    def _is_pattern(addr):
        if addr in _pattern_addrs:
            return True
        # Repeating hex nibble: 0xAAAAAAAAAAAAAAAA etc
        h = hex(addr)[2:]
        return len(h) >= 8 and len(set(h)) == 1

    trace_parts = []
    for frame in (report.crash_trace or [])[:15]:
        loc = ""
        if frame.source_file:
            loc = f'<span class="frame-loc">{frame.source_file}:{frame.line}</span>'
        elif frame.module:
            loc = f'<span class="frame-loc">({frame.module})</span>'
        controlled = _is_pattern(frame.address)
        frame_cls = "stack-frame stack-frame-controlled" if controlled else "stack-frame"
        addr_cls = "frame-addr frame-addr-controlled" if controlled else "frame-addr"
        func_cls = "frame-func frame-func-controlled" if controlled else "frame-func"
        tag = '<span class="frame-controlled-tag">CONTROLLED</span>' if controlled else ""
        trace_parts.append(f'''<div class="{frame_cls}">
            <span class="frame-num">#{frame.frame_num}</span>
            <span class="{addr_cls}">{hex(frame.address)}</span>
            <span class="{func_cls}">{frame.function or "??"}</span>
            {loc}{tag}</div>''')
    trace_html = '\n'.join(trace_parts)

    factors_html = "".join(f"<li>{f}</li>" for f in analysis["factors"])

    # Heap info
    heap_html = ""
    if report.heap_info:
        hi = report.heap_info
        alloc_html = _trace_to_html(hi.alloc_trace[:5])
        free_html = _trace_to_html(hi.free_trace[:5])
        heap_html = f'''<div class="card">
            <h2>Heap Information</h2>
            <p style="margin-bottom:12px;color:var(--text-dim);">{hi.region_size}B region, {hi.offset}B {hi.direction}, state: {hi.chunk_state or "allocated"}</p>
            <div class="two-col">
                <div><h3 style="font-size:13px;color:var(--green);margin-bottom:8px;">Allocation Trace</h3><div class="stack-trace">{alloc_html or "<em style='color:var(--text-dim)'>N/A</em>"}</div></div>
                <div><h3 style="font-size:13px;color:var(--red);margin-bottom:8px;">Free Trace</h3><div class="stack-trace">{free_html or "<em style='color:var(--text-dim)'>N/A</em>"}</div></div>
            </div></div>'''

    # Root Cause Analysis section
    rca = result.get("root_cause")
    rca_html = ""
    if rca and (rca.explanation or rca.source_contexts):
        rca_sections = ""

        if rca.explanation:
            pattern_badge = f'<span class="severity-badge severity-HIGH" style="font-size:11px;padding:2px 8px;margin-left:8px">{rca.vulnerability_pattern}</span>' if rca.vulnerability_pattern else ""
            suggestions_html = ""
            if rca.suggestions:
                suggestions_html = '<div style="margin-top:12px"><strong style="color:var(--accent)">Suggestions:</strong><ul style="margin-top:4px">'
                for s in rca.suggestions:
                    suggestions_html += f'<li style="color:var(--text);padding:4px 0">{_esc(s)}</li>'
                suggestions_html += '</ul></div>'

            rca_sections += f'''<div class="card">
                <h2>Root Cause {pattern_badge}</h2>
                <p style="line-height:1.8;font-size:14px">{_esc(rca.explanation)}</p>
                {suggestions_html}
            </div>'''

        for ctx in rca.source_contexts:
            ann_map = {}
            for a in ctx.annotations:
                ann_map[a["line"]] = a

            code_lines = ""
            for num, text in ctx.lines:
                escaped = _esc(text)
                ann = ann_map.get(num)
                ann_html = ""
                if ann:
                    ann_color = "var(--red)" if ann["severity"] == "critical" else "var(--orange)"
                    ann_html = f'<span style="color:{ann_color};font-weight:bold;margin-left:16px">{_esc(ann["text"])}</span>'

                if num == ctx.highlight_line:
                    code_lines += f'<div class="code-line code-highlight"><span class="line-num">{num}</span><span class="line-text">{escaped}</span>{ann_html}</div>\n'
                elif ann:
                    code_lines += f'<div class="code-line code-annotated"><span class="line-num">{num}</span><span class="line-text">{escaped}</span>{ann_html}</div>\n'
                else:
                    code_lines += f'<div class="code-line"><span class="line-num">{num}</span><span class="line-text">{escaped}</span></div>\n'

            rca_sections += f'''<div class="card">
                <h2>Source: {_esc(ctx.function)}() — {_esc(Path(ctx.file_path).name)}:{ctx.line_num}</h2>
                <div class="source-viewer">{code_lines}</div>
            </div>'''

        rca_html = rca_sections

    # CWE badge
    cwe = result.get("cwe", {})
    cwe_html = ""
    if cwe:
        cwe_html = f'<a href="{cwe["url"]}" target="_blank" style="color:var(--cyan);text-decoration:none;font-size:13px;margin-left:8px">{cwe["id"]}: {cwe["name"]}</a>'

    # Binary security card
    bin_sec = result.get("binary_security")
    checksec_html = ""
    if bin_sec:
        def _sec_badge(val, label):
            color = "var(--green)" if val else "var(--red)"
            icon = "✅" if val else "❌"
            return f'<span style="margin-right:16px">{label} {icon}</span>'
        relro_color = "var(--green)" if bin_sec.relro == "Full" else ("var(--orange)" if bin_sec.relro == "Partial" else "var(--red)")
        checksec_html = f'''<div class="card">
            <h2>Target Hardening</h2>
            <div style="font-size:14px;line-height:2">
                {_sec_badge(bin_sec.pie, "PIE")}
                {_sec_badge(bin_sec.nx, "NX")}
                <span style="margin-right:16px">RELRO: <span style="color:{relro_color}">{bin_sec.relro}</span></span>
                {_sec_badge(bin_sec.canary, "Canary")}
                {_sec_badge(bin_sec.fortify, "FORTIFY")}
            </div>
            <p style="margin-top:8px;font-size:12px;color:var(--text-dim)">{bin_sec.arch} ({bin_sec.bits}-bit)</p>
        </div>'''

    # Exploitation hints
    hints = result.get("exploitation_hints", [])
    hints_html = ""
    if hints:
        hints_items = "".join(f'<li style="padding:4px 0;color:var(--text)">{_esc(h)}</li>' for h in hints)
        hints_html = f'''<div class="card">
            <h2>Exploitation Notes</h2>
            <ul style="list-style:none;padding:0">{hints_items}</ul>
        </div>'''

    raw_log = result.get("raw_log", "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wendigo — {report.bug_type} — {Path(source).name if source else "report"}</title>
{'<link rel="stylesheet" href="style.css">' if external_assets else f'<style>{css}</style>'}
<style>
details {{ margin-top: 16px; }}
details summary {{ cursor: pointer; color: var(--text-dim); font-size: 13px; }}
details pre {{ background: var(--bg); padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: var(--text-dim); margin-top: 8px; white-space: pre-wrap; word-break: break-all; }}
</style>
</head>
<body>
<header><div class="container">
    <h1>👁 <span>Wendigo</span> {kasan_badge}</h1>
    <div class="header-actions">
        <button class="btn" onclick="exportPNG()">Export Diagram PNG</button>
    </div>
</div></header>
<div class="container">
    <div class="card">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item"><label>Bug Type</label><div class="value">{report.bug_type}{' ' + cwe_html if cwe_html else ''}</div></div>
            <div class="summary-item"><label>Category</label><div class="value">{report.bug_category}{" (kernel)" if report.is_kasan else ""}</div></div>
            <div class="summary-item"><label>Access</label><div class="value">{report.access_type} of {report.access_size} bytes</div></div>
            <div class="summary-item"><label>Address</label><div class="value" style="font-family:'SF Mono',monospace;font-size:14px;">{hex(report.access_address) if report.access_address else "N/A"}</div></div>
            <div class="summary-item"><label>Severity</label><div><span class="severity-badge severity-{sev_class}">{sev}</span></div></div>
            <div class="summary-item"><label>Score</label><div class="value">{analysis["score"]}/100</div></div>
        </div>
        <div class="one-liner">{analysis["one_liner"]}</div>
        <p style="margin-top:8px;font-size:12px;color:var(--text-dim);">Source: {Path(source).name if source else "N/A"}</p>
    </div>
    <div class="card"><h2>Memory Visualization</h2><div id="diagram-container"></div></div>
    <div class="two-col">
        <div class="card"><h2>Exploitability Factors</h2><ul class="factors-list">{factors_html}</ul></div>
        <div class="card"><h2>Crash Stack Trace</h2><div class="stack-trace">{trace_html}</div></div>
    </div>
    {_generate_registers_html(report) if report.is_gdb else ""}
    {checksec_html}
    {hints_html}
    {heap_html}
    {rca_html}
    <div class="card">
        <details><summary>Raw {"GDB" if report.is_gdb else "KASAN" if report.is_kasan else "ASAN"} Output</summary><pre>{raw_log}</pre></details>
    </div>
</div>
<div class="svg-tooltip" id="tooltip"></div>
<script id="report-data" type="application/json">{data}</script>
{'<script src="diagrams.js"></script>' if external_assets else f'<script>{js}</script>'}
<footer style="text-align:center;padding:24px 0 32px;color:var(--text-dim,#8b949e);font-size:12px">👁 Wendigo — by <a href="https://github.com/oxmesh" style="color:var(--accent,#58a6ff);text-decoration:none">Mesh</a></footer>
</body>
</html>'''
def _generate_registers_html(report):
    """Generate HTML card showing GDB register state."""
    if not report.registers:
        return ""
    pattern_vals = {0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
                    0x4444444444444444, 0x4545454545454545, 0x4646464646464646}
    rows = []
    important_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
    for reg in important_regs:
        if reg not in report.registers:
            continue
        val = report.registers[reg]
        hexval = f"0x{val:016x}"
        if val in pattern_vals:
            rows.append(f'<tr style="color:#f85149;font-weight:bold"><td>{reg}</td><td>{hexval}</td><td>⚠ CONTROLLED</td></tr>')
        elif reg == "rip":
            rows.append(f'<tr style="color:#bc8cff"><td>{reg}</td><td>{hexval}</td><td>← crash</td></tr>')
        else:
            rows.append(f'<tr style="color:var(--text-dim)"><td>{reg}</td><td>{hexval}</td><td></td></tr>')
    return f'''<div class="card"><h2>Register State</h2>
    <table style="width:100%;font-family:'SF Mono',monospace;font-size:13px;border-collapse:collapse">
    <thead><tr style="color:var(--text-dim);border-bottom:1px solid var(--border)">
    <th style="text-align:left;padding:4px 12px">Register</th>
    <th style="text-align:left;padding:4px 12px">Value</th>
    <th style="text-align:left;padding:4px 12px">Status</th></tr></thead>
    <tbody>{"".join(rows)}</tbody></table></div>'''
def _esc(text):
    """HTML escape."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
def _trace_to_html(frames):
    parts = []
    for f in (frames or []):
        parts.append(f'<div class="stack-frame"><span class="frame-num">#{f.frame_num}</span><span class="frame-addr">{hex(f.address)}</span><span class="frame-func">{f.function or "??"}</span></div>')
    return '\n'.join(parts)
def _generate_index(results, out_dir, afl_stats=None):
    """Generate an index.html listing all triaged crashes with sortable columns."""
    rows = ""
    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NOT EXPLOITABLE": 1}
    for r in sorted(results, key=lambda x: x["analysis"]["score"], reverse=True):
        report = r["report"]
        analysis = r["analysis"]
        name = Path(r["source"]).name
        safe = _safe_name(name)
        sev = analysis["severity"]
        sev_class = sev.replace(" ", "-")
        func = report.crash_trace[0].function if report.crash_trace else "?"
        rows += f'''<tr onclick="window.location='{safe}.html'" style="cursor:pointer" data-score="{analysis["score"]}" data-sevord="{sev_order.get(sev, 0)}">
            <td style="font-family:monospace;font-size:12px">{name[:50]}</td>
            <td>{report.bug_type}</td>
            <td>{report.access_type} {report.access_size}B</td>
            <td><span class="severity-badge severity-{sev_class}" style="font-size:11px;padding:2px 8px">{sev}</span></td>
            <td>{analysis["score"]}</td>
            <td>{func}</td>
        </tr>\n'''

    # Severity distribution pie chart (pure SVG)
    sev_counts = Counter(r["analysis"]["severity"] for r in results)
    pie_svg = _generate_pie_chart(sev_counts, len(results))

    # Timeline (if AFL++ timestamps in filenames)
    timeline_svg = _generate_timeline(results)

    # AFL++ stats header
    afl_header = ""
    if afl_stats:
        afl_header = '<div class="card"><h2>AFL++ Stats</h2><div class="summary-grid">'
        for key in ["execs_done", "execs_per_sec", "run_time", "corpus_count", "saved_crashes"]:
            if key in afl_stats:
                label = key.replace("_", " ").title()
                afl_header += f'<div class="summary-item"><label>{label}</label><div class="value">{afl_stats[key]}</div></div>'
        afl_header += '</div></div>'

    sort_js = '''
<script>
(function() {
    var table = document.querySelector("table");
    var headers = table.querySelectorAll("th");
    var tbody = table.querySelector("tbody");
    var sortCol = -1, sortAsc = true;

    function getSortVal(row, col) {
        if (col === 4) return parseFloat(row.getAttribute("data-score")) || 0;
        if (col === 3) return parseFloat(row.getAttribute("data-sevord")) || 0;
        return row.cells[col].textContent.trim().toLowerCase();
    }

    function sortTable(col) {
        if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = (col === 4 || col === 3) ? false : true; }
        var rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort(function(a, b) {
            var va = getSortVal(a, col), vb = getSortVal(b, col);
            if (typeof va === "number") return sortAsc ? va - vb : vb - va;
            return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
        });
        rows.forEach(function(r) { tbody.appendChild(r); });
        headers.forEach(function(h, i) {
            h.textContent = h.textContent.replace(/ [▲▼]$/, "");
            if (i === col) h.textContent += sortAsc ? " ▲" : " ▼";
        });
    }

    headers.forEach(function(h, i) {
        h.style.cursor = "pointer";
        h.addEventListener("click", function() { sortTable(i); });
    });
})();
</script>'''

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Wendigo — Batch Triage Results</title>
<link rel="stylesheet" href="style.css">
<style>
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }}
th {{ color: var(--text-dim); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; user-select: none; }}
tr:hover {{ background: var(--bg3); }}
.stats-row {{ display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap; }}
.stats-row .card {{ flex: 1; min-width: 300px; }}
</style></head><body>
<header><div class="container"><h1>👁 <span>Wendigo</span> — Batch Results</h1></div></header>
<div class="container">
{afl_header}
<div class="stats-row">
<div class="card"><h2>Severity Distribution</h2>{pie_svg}</div>
{f'<div class="card"><h2>Crash Discovery Timeline</h2>{timeline_svg}</div>' if timeline_svg else ''}
</div>
<div class="card">
<h2>{len(results)} Crashes Triaged</h2>
<table><thead><tr><th>Crash</th><th>Type</th><th>Access</th><th>Severity</th><th>Score</th><th>Function</th></tr></thead>
<tbody>{rows}</tbody></table>
</div></div>
{sort_js}
</body></html>'''

    (out_dir / "index.html").write_text(html)
def _generate_pie_chart(sev_counts, total):
    """Generate a pure SVG pie chart for severity distribution."""
    if total == 0:
        return "<p>No data</p>"

    colors = {
        "CRITICAL": "#f85149",
        "HIGH": "#da3633",
        "MEDIUM": "#d29922",
        "LOW": "#58a6ff",
        "NOT EXPLOITABLE": "#3fb950",
    }

    cx, cy, r = 100, 100, 80
    svg_parts = [f'<svg viewBox="0 0 300 220" xmlns="http://www.w3.org/2000/svg" style="max-width:400px;width:100%">']

    start_angle = 0
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT EXPLOITABLE"]:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        pct = count / total
        angle = pct * 360

        # SVG arc
        end_angle = start_angle + angle
        large_arc = 1 if angle > 180 else 0

        x1 = cx + r * math.cos(math.radians(start_angle - 90))
        y1 = cy + r * math.sin(math.radians(start_angle - 90))
        x2 = cx + r * math.cos(math.radians(end_angle - 90))
        y2 = cy + r * math.sin(math.radians(end_angle - 90))

        if pct >= 1.0:
            # Full circle
            svg_parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{colors[sev]}"/>')
        else:
            path = f'M {cx},{cy} L {x1:.1f},{y1:.1f} A {r},{r} 0 {large_arc},1 {x2:.1f},{y2:.1f} Z'
            svg_parts.append(f'<path d="{path}" fill="{colors[sev]}"/>')

        start_angle = end_angle

    # Legend
    ly = 10
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT EXPLOITABLE"]:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        svg_parts.append(f'<rect x="210" y="{ly}" width="12" height="12" rx="2" fill="{colors[sev]}"/>')
        svg_parts.append(f'<text x="228" y="{ly+10}" font-size="11" fill="#c9d1d9" font-family="sans-serif">{sev} ({count})</text>')
        ly += 20

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)
def _generate_timeline(results):
    """Generate SVG timeline if crash filenames contain AFL++ timestamps."""
    # AFL++ crash files: id:000000,sig:11,src:000000,time:123456,execs:789
    timestamps = []
    for r in results:
        name = Path(r["source"]).name
        m = re.search(r"time:(\d+)", name)
        if m:
            timestamps.append((int(m.group(1)), r["analysis"]["severity"]))

    if len(timestamps) < 2:
        return ""

    timestamps.sort()
    min_t = timestamps[0][0]
    max_t = timestamps[-1][0]
    span = max_t - min_t
    if span == 0:
        return ""

    colors = {
        "CRITICAL": "#f85149", "HIGH": "#da3633", "MEDIUM": "#d29922",
        "LOW": "#58a6ff", "NOT EXPLOITABLE": "#3fb950",
    }

    w, h = 500, 120
    pad_x, pad_y = 40, 20
    plot_w = w - 2 * pad_x
    plot_h = h - 2 * pad_y

    svg = [f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" style="width:100%">']
    # Axis
    svg.append(f'<line x1="{pad_x}" y1="{h-pad_y}" x2="{w-pad_x}" y2="{h-pad_y}" stroke="#30363d" stroke-width="1"/>')

    # Cumulative line
    points = []
    for i, (t, sev) in enumerate(timestamps):
        x = pad_x + (t - min_t) / span * plot_w
        y = h - pad_y - ((i + 1) / len(timestamps)) * plot_h
        points.append(f"{x:.1f},{y:.1f}")
        svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colors.get(sev, "#58a6ff")}"/>')

    svg.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="#58a6ff" stroke-width="1.5" opacity="0.5"/>')

    # Labels
    svg.append(f'<text x="{pad_x}" y="{h-3}" font-size="9" fill="#8b949e" font-family="sans-serif">{min_t}s</text>')
    svg.append(f'<text x="{w-pad_x}" y="{h-3}" font-size="9" fill="#8b949e" font-family="sans-serif" text-anchor="end">{max_t}s</text>')
    svg.append(f'<text x="{w//2}" y="{h-3}" font-size="9" fill="#8b949e" font-family="sans-serif" text-anchor="middle">Time →</text>')
    svg.append(f'<text x="{pad_x-5}" y="{pad_y+5}" font-size="9" fill="#8b949e" font-family="sans-serif" text-anchor="end">{len(timestamps)}</text>')

    svg.append('</svg>')
    return "\n".join(svg)
def _report_name(crash_path):
    return _safe_name(Path(crash_path).name) + ".html"

def _safe_name(name):
    return name.replace(",", "_").replace(":", "_").replace(" ", "_")[:80]
if __name__ == "__main__":
    main()

