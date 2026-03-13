"""
Root Cause Analysis — trace from crash back to the vulnerable code.

Given an ASAN report with stack traces and source file paths,
read the actual source, identify the vulnerability pattern, and
annotate the root cause.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .parser import AsanReport, StackFrame


@dataclass
class SourceContext:
    """A snippet of source code around a crash point."""
    file_path: str
    line_num: int
    function: str
    lines: list[tuple[int, str]] = field(default_factory=list)  # (line_num, text)
    highlight_line: int = 0  # the crash line
    annotations: list[dict] = field(default_factory=list)  # [{line, text, severity}]

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "line_num": self.line_num,
            "function": self.function,
            "lines": [{"num": n, "text": t} for n, t in self.lines],
            "highlight_line": self.highlight_line,
            "annotations": self.annotations,
        }


@dataclass
class RootCauseResult:
    """Full root cause analysis result."""
    root_cause_frame: Optional[dict] = None  # which stack frame is the root cause
    root_cause_line: int = 0
    root_cause_file: str = ""
    root_cause_function: str = ""
    explanation: str = ""
    vulnerability_pattern: str = ""  # "missing-bounds-check", "integer-overflow", etc.
    source_contexts: list[SourceContext] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "root_cause_frame": self.root_cause_frame,
            "root_cause_line": self.root_cause_line,
            "root_cause_file": self.root_cause_file,
            "root_cause_function": self.root_cause_function,
            "explanation": self.explanation,
            "vulnerability_pattern": self.vulnerability_pattern,
            "source_contexts": [s.to_dict() for s in self.source_contexts],
            "suggestions": self.suggestions,
        }


# Patterns that indicate vulnerability root causes
VULN_PATTERNS = {
    "missing-bounds-check": [
        r"\bfor\s*\([^)]*;\s*\w+\s*[<>]=?\s*\w+\s*;",  # loop with potential OOB
        r"\[\s*\w+\s*\]",  # array access
        r"memcpy|memmove|memset|strcpy|strncpy|sprintf|strcat",
    ],
    "integer-overflow": [
        r"\*\s*(?:sizeof|size|len|count|num|width|height)",  # multiplication with size
        r"(?:size|len|count|num)\s*\*",
        r"\(\s*\w+\s*\+\s*\w+\s*\)\s*\*",  # (a + b) * c
        r"<<\s*\d+",  # left shift
    ],
    "unchecked-allocation": [
        r"malloc\s*\(|calloc\s*\(|realloc\s*\(",
        r"new\s+\w+",
        r"g_malloc|g_new|g_realloc",
    ],
    "format-string": [
        r"printf\s*\(\s*\w+|sprintf\s*\(\s*\w+\s*,\s*\w+",
    ],
    "use-after-free": [
        r"free\s*\(|g_free\s*\(|delete\s+",
    ],
    "uninitialized": [
        r"^\s*\w+\s+\w+\s*;",  # declaration without initialization
    ],
}

# Bug type → likely patterns to look for
BUG_PATTERN_MAP = {
    "heap-buffer-overflow": ["missing-bounds-check", "integer-overflow", "unchecked-allocation"],
    "heap-buffer-underflow": ["missing-bounds-check", "integer-overflow"],
    "stack-buffer-overflow": ["missing-bounds-check"],
    "heap-use-after-free": ["use-after-free"],
    "double-free": ["use-after-free"],
    "null-deref": ["unchecked-allocation"],
    "stack-buffer-underflow": ["missing-bounds-check"],
}

# Context lines to show around crash point
CONTEXT_LINES = 15


def analyze_root_cause(report: AsanReport, source_dir: str = None) -> RootCauseResult:
    """
    Perform root cause analysis by reading source files from stack traces.

    Args:
        report: Parsed ASAN report
        source_dir: Optional base directory to resolve source paths.
                    If source paths in ASAN are /build/src/foo.c and source_dir
                    is /home/user/project, tries to find foo.c under source_dir.
    """
    result = RootCauseResult()

    # Collect all frames with source info
    all_frames = []
    if report.crash_trace:
        all_frames.extend(report.crash_trace)
    if report.heap_info:
        if report.heap_info.alloc_trace:
            all_frames.extend(report.heap_info.alloc_trace)
        if report.heap_info.free_trace:
            all_frames.extend(report.heap_info.free_trace)

    # Try to read source for each crash frame
    for frame in report.crash_trace[:8]:
        # KASAN frames: no source file, try resolving by function name
        if (not frame.source_file or not frame.line) and source_dir and frame.function:
            resolved, line = _resolve_kernel_function(frame.function, source_dir)
            if resolved and line:
                ctx = _read_source_context(resolved, line, frame.function)
                if ctx:
                    ctx.annotations.append({
                        "line": line,
                        "text": f"← crash in {frame.function}()",
                        "severity": "critical",
                    })
                    result.source_contexts.append(ctx)
            continue

        if not frame.source_file or not frame.line:
            continue

        resolved = _resolve_source(frame.source_file, source_dir)
        if not resolved:
            continue

        ctx = _read_source_context(resolved, frame.line, frame.function)
        if ctx:
            result.source_contexts.append(ctx)

    # Also read alloc/free traces for UAF/double-free
    if report.bug_type in ("heap-use-after-free", "double-free") and report.heap_info:
        for trace_name, trace in [("alloc", report.heap_info.alloc_trace),
                                   ("free", report.heap_info.free_trace)]:
            for frame in (trace or [])[:3]:
                if not frame.source_file or not frame.line:
                    continue
                # Skip sanitizer/libc internals
                if any(x in frame.source_file for x in ["asan", "sanitizer", "libc", "libstdc++"]):
                    continue
                resolved = _resolve_source(frame.source_file, source_dir)
                if not resolved:
                    continue
                ctx = _read_source_context(resolved, frame.line, frame.function)
                if ctx:
                    ctx.annotations.append({
                        "line": frame.line,
                        "text": f"← {trace_name}() happens here",
                        "severity": "critical" if trace_name == "free" else "info",
                    })
                    result.source_contexts.append(ctx)

    # Analyze patterns in source code
    if result.source_contexts:
        _analyze_patterns(report, result)

    return result


def _resolve_kernel_function(func_name: str, source_dir: str) -> tuple[Optional[str], Optional[int]]:
    """
    Resolve a kernel function name to source file + line using grep.
    For KASAN traces that only have func+offset, no source info.
    Strips .isra.N / .constprop.N suffixes.
    """
    import subprocess

    # Strip compiler suffixes
    clean = re.sub(r'\.(isra|constprop|cold|part)\.\d+$', '', func_name)
    # Skip generic kernel/sanitizer functions
    skip = {'kasan_save_stack', 'kasan_save_track', 'kasan_report', '__asan_store',
            '__asan_load', 'kmalloc', 'kfree', '__slab_alloc', 'kmem_cache_alloc',
            'memcpy', 'memmove', 'memset', '__memcpy', '__memmove'}
    if clean in skip:
        return None, None

    try:
        # Use grep to find function definition
        result = subprocess.run(
            ['grep', '-rn', f'^[a-zA-Z_].*\\b{clean}\\s*(', source_dir,
             '--include=*.c', '--include=*.h', '-l'],
            capture_output=True, text=True, timeout=10
        )
        if not result.stdout.strip():
            # Try broader pattern
            result = subprocess.run(
                ['grep', '-rn', f'\\b{clean}\\b', source_dir,
                 '--include=*.c', '-l'],
                capture_output=True, text=True, timeout=10
            )

        files = result.stdout.strip().split('\n')
        if not files or not files[0]:
            return None, None

        # Pick the most likely file (prefer non-header, shorter path)
        best = sorted([f for f in files if f.endswith('.c')],
                      key=lambda x: len(x))
        target = best[0] if best else files[0]

        # Find the actual function definition line
        result2 = subprocess.run(
            ['grep', '-n', f'\\b{clean}\\s*(', target],
            capture_output=True, text=True, timeout=5
        )
        if result2.stdout.strip():
            for line in result2.stdout.strip().split('\n'):
                m = re.match(r'^(\d+):', line)
                if m:
                    return target, int(m.group(1))

        return target, 1
    except (subprocess.TimeoutExpired, Exception):
        return None, None


def _resolve_source(file_path: str, source_dir: str = None) -> Optional[str]:
    """Try to resolve a source file path to an actual file on disk."""
    # Direct path
    if os.path.isfile(file_path):
        return file_path

    if not source_dir:
        return None

    source_dir = str(Path(source_dir).resolve())

    # Try stripping build prefixes and searching under source_dir
    # Common: /path/to/build/src/file.c → source_dir/src/file.c
    path = Path(file_path)
    parts = path.parts

    # Try progressively shorter suffixes
    for i in range(len(parts)):
        candidate = Path(source_dir) / Path(*parts[i:])
        if candidate.is_file():
            return str(candidate)

    # Try just the filename
    for root, dirs, files in os.walk(source_dir):
        if path.name in files:
            return os.path.join(root, path.name)
        # Don't recurse too deep
        depth = root.replace(source_dir, "").count(os.sep)
        if depth > 5:
            dirs.clear()

    return None


def _read_source_context(file_path: str, line_num: int, function: str) -> Optional[SourceContext]:
    """Read source code around a specific line."""
    try:
        with open(file_path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except (IOError, OSError):
        return None

    total = len(all_lines)
    if line_num < 1 or line_num > total:
        return None

    start = max(1, line_num - CONTEXT_LINES)
    end = min(total, line_num + CONTEXT_LINES)

    lines = [(i, all_lines[i - 1].rstrip()) for i in range(start, end + 1)]

    ctx = SourceContext(
        file_path=file_path,
        line_num=line_num,
        function=function,
        lines=lines,
        highlight_line=line_num,
    )

    return ctx


def _analyze_patterns(report: AsanReport, result: RootCauseResult):
    """Analyze source code patterns to identify the vulnerability root cause."""
    bt = report.bug_type
    likely_patterns = BUG_PATTERN_MAP.get(bt, ["missing-bounds-check"])

    # Look at the first (topmost) source context — that's the crash site
    if not result.source_contexts:
        return

    crash_ctx = result.source_contexts[0]
    crash_line_text = ""
    for num, text in crash_ctx.lines:
        if num == crash_ctx.highlight_line:
            crash_line_text = text
            break

    # Collect surrounding code as one block for pattern matching
    surrounding = "\n".join(text for _, text in crash_ctx.lines)

    # Check for vulnerability patterns
    found_patterns = []
    for pattern_name in likely_patterns:
        regexes = VULN_PATTERNS.get(pattern_name, [])
        for regex in regexes:
            matches = list(re.finditer(regex, surrounding))
            if matches:
                found_patterns.append(pattern_name)
                break

    # Annotate based on bug type and found patterns
    if bt in ("heap-buffer-overflow", "heap-buffer-underflow", "stack-buffer-overflow"):
        _annotate_overflow(report, result, crash_ctx, surrounding, found_patterns)
    elif bt in ("heap-use-after-free", "double-free"):
        _annotate_uaf(report, result, crash_ctx, surrounding)
    elif bt == "null-deref":
        _annotate_null_deref(report, result, crash_ctx, surrounding)
    else:
        _annotate_generic(report, result, crash_ctx, surrounding, found_patterns)

    # Set the root cause frame
    if report.crash_trace:
        # Walk up the stack to find the frame most likely responsible
        root_frame = _find_root_cause_frame(report, result)
        if root_frame:
            result.root_cause_frame = root_frame.to_dict()
            result.root_cause_line = root_frame.line
            result.root_cause_file = root_frame.source_file
            result.root_cause_function = root_frame.function


def _annotate_overflow(report, result, crash_ctx, surrounding, found_patterns):
    """Annotate heap/stack buffer overflow."""
    hi = report.heap_info
    si = report.stack_info

    # Look for array accesses on the crash line
    for num, text in crash_ctx.lines:
        if num == crash_ctx.highlight_line:
            # Array access?
            if re.search(r'\[.*\]', text):
                crash_ctx.annotations.append({
                    "line": num,
                    "text": f"← CRASH: {report.access_type} of {report.access_size}B out of bounds here",
                    "severity": "critical",
                })
            # memcpy/memmove?
            elif re.search(r'memcpy|memmove|memset|strcpy|strncpy|sprintf|strcat|bcopy', text):
                crash_ctx.annotations.append({
                    "line": num,
                    "text": f"← CRASH: Unsafe memory operation — {report.access_type} overflows buffer by {hi.offset if hi else '?'}B",
                    "severity": "critical",
                })
            else:
                crash_ctx.annotations.append({
                    "line": num,
                    "text": f"← CRASH: {report.access_type} of {report.access_size}B",
                    "severity": "critical",
                })
            break

    # Look for missing bounds checks above the crash line
    has_bounds_check = False
    for num, text in crash_ctx.lines:
        if num >= crash_ctx.highlight_line:
            break
        if re.search(r'if\s*\(.*(?:len|size|count|index|offset|i|j|k)\s*[<>]=?', text):
            has_bounds_check = True
            break
        if re.search(r'assert\s*\(', text):
            has_bounds_check = True
            break

    if not has_bounds_check:
        result.suggestions.append("No bounds check found before the crash point — add validation")
        result.vulnerability_pattern = "missing-bounds-check"
        result.explanation = (
            f"The {report.access_type.lower()} at {crash_ctx.function}() accesses memory "
            f"{hi.offset if hi else '?'} bytes beyond the allocated "
            f"{hi.region_size if hi else '?'}-byte buffer. "
            f"No bounds validation was found before the access point."
        )
    elif "integer-overflow" in found_patterns:
        result.vulnerability_pattern = "integer-overflow"
        result.explanation = (
            f"An integer overflow in size calculation likely causes an undersized allocation, "
            f"leading to a {report.access_type.lower()} of {report.access_size} bytes "
            f"past the buffer boundary."
        )
        result.suggestions.append("Check for integer overflow in size calculations before allocation")
    else:
        result.vulnerability_pattern = "insufficient-bounds-check"
        result.explanation = (
            f"A bounds check exists but is insufficient — the {report.access_type.lower()} "
            f"still goes {hi.offset if hi else '?'} bytes out of bounds."
        )
        result.suggestions.append("Review bounds check logic — off-by-one or incorrect comparison")

    # Look for the allocation site
    if hi and hi.alloc_trace:
        for frame in hi.alloc_trace:
            if frame.function and frame.function not in ("malloc", "calloc", "realloc",
                                                          "__interceptor_malloc", "operator new"):
                result.suggestions.append(
                    f"Check allocation size in {frame.function}() — buffer may be undersized"
                )
                break

    # Look for loop patterns
    for num, text in crash_ctx.lines:
        if re.search(r'\bfor\s*\(', text) and num <= crash_ctx.highlight_line:
            if re.search(r'<\s*\w+', text):
                crash_ctx.annotations.append({
                    "line": num,
                    "text": "← Loop bound — verify this limit matches buffer size",
                    "severity": "warning",
                })


def _annotate_uaf(report, result, crash_ctx, surrounding):
    """Annotate use-after-free."""
    for num, text in crash_ctx.lines:
        if num == crash_ctx.highlight_line:
            crash_ctx.annotations.append({
                "line": num,
                "text": f"← CRASH: Accessing freed memory ({report.access_type} {report.access_size}B)",
                "severity": "critical",
            })
            break

    result.vulnerability_pattern = "use-after-free"

    hi = report.heap_info
    free_func = ""
    if hi and hi.free_trace:
        for f in hi.free_trace:
            if f.function not in ("free", "__interceptor_free", "operator delete", "g_free"):
                free_func = f.function
                break

    result.explanation = (
        f"Memory was freed"
        f"{' in ' + free_func + '()' if free_func else ''} "
        f"but a dangling pointer is still used in {crash_ctx.function}(). "
        f"The {report.access_type.lower()} of {report.access_size} bytes "
        f"accesses the freed {hi.region_size if hi else '?'}-byte region."
    )
    result.suggestions.append("Set pointer to NULL after free")
    result.suggestions.append("Check object lifetime — ensure consumer doesn't outlive producer")
    if report.access_type == "WRITE":
        result.suggestions.append("⚠ WRITE to freed memory — attacker can control reallocated content")


def _annotate_null_deref(report, result, crash_ctx, surrounding):
    """Annotate null pointer dereference."""
    for num, text in crash_ctx.lines:
        if num == crash_ctx.highlight_line:
            crash_ctx.annotations.append({
                "line": num,
                "text": f"← CRASH: Null pointer dereference ({report.access_type})",
                "severity": "critical",
            })
            break

    result.vulnerability_pattern = "null-deref"
    result.explanation = (
        f"Null pointer dereference in {crash_ctx.function}(). "
        f"A pointer is used without checking for NULL first."
    )
    result.suggestions.append("Add NULL check before dereferencing the pointer")

    # Look for malloc/calloc without null check
    for num, text in crash_ctx.lines:
        if num < crash_ctx.highlight_line:
            if re.search(r'malloc|calloc|realloc|g_malloc|g_new', text):
                crash_ctx.annotations.append({
                    "line": num,
                    "text": "← Allocation here — return value may be NULL",
                    "severity": "warning",
                })


def _annotate_generic(report, result, crash_ctx, surrounding, found_patterns):
    """Generic annotation."""
    for num, text in crash_ctx.lines:
        if num == crash_ctx.highlight_line:
            crash_ctx.annotations.append({
                "line": num,
                "text": f"← CRASH: {report.bug_type} ({report.access_type} {report.access_size}B)",
                "severity": "critical",
            })
            break

    if found_patterns:
        result.vulnerability_pattern = found_patterns[0]
    else:
        result.vulnerability_pattern = "unknown"

    result.explanation = (
        f"{report.bug_type.replace('-', ' ').title()} in {crash_ctx.function}(). "
        f"{report.access_type} of {report.access_size} bytes at {hex(report.access_address)}."
    )


def _find_root_cause_frame(report: AsanReport, result: RootCauseResult) -> Optional[StackFrame]:
    """
    Walk up the crash stack trace to find the frame most likely responsible.
    Skip sanitizer/libc internals. Prefer frames with source info.
    """
    skip_prefixes = ("__asan", "__sanitizer", "__interceptor", "__libc_start",
                     "_start", "__GI_", "abort", "raise")

    for frame in report.crash_trace:
        if not frame.function:
            continue
        if any(frame.function.startswith(p) for p in skip_prefixes):
            continue
        if frame.source_file and any(x in frame.source_file for x in
                                      ["asan", "sanitizer", "libc-start", "csu/"]):
            continue
        return frame

    # Fallback: first frame
    return report.crash_trace[0] if report.crash_trace else None

