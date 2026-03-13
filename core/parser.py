"""ASAN output parser - extracts bug type, addresses, stack traces, heap metadata."""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StackFrame:
    frame_num: int
    address: int
    function: str = ""
    source_file: str = ""
    line: int = 0
    column: int = 0
    module: str = ""

    def to_dict(self):
        return {
            "frame_num": self.frame_num,
            "address": hex(self.address),
            "function": self.function,
            "source_file": self.source_file,
            "line": self.line,
            "column": self.column,
            "module": self.module,
        }


@dataclass
class HeapInfo:
    address: int = 0
    region_size: int = 0
    offset: int = 0  # bytes to left/right of region
    direction: str = ""  # "right", "left", "inside"
    alloc_thread: int = 0
    free_thread: int = 0
    alloc_trace: list = field(default_factory=list)
    free_trace: list = field(default_factory=list)
    chunk_state: str = ""  # "allocated", "freed"

    def to_dict(self):
        return {
            "address": hex(self.address),
            "region_size": self.region_size,
            "offset": self.offset,
            "direction": self.direction,
            "alloc_thread": self.alloc_thread,
            "free_thread": self.free_thread,
            "alloc_trace": [f.to_dict() for f in self.alloc_trace],
            "free_trace": [f.to_dict() for f in self.free_trace],
            "chunk_state": self.chunk_state,
        }


@dataclass
class StackInfo:
    variable_name: str = ""
    variable_size: int = 0
    frame_function: str = ""
    offset: int = 0
    direction: str = ""

    def to_dict(self):
        return {
            "variable_name": self.variable_name,
            "variable_size": self.variable_size,
            "frame_function": self.frame_function,
            "offset": self.offset,
            "direction": self.direction,
        }


@dataclass
class AsanReport:
    raw_log: str = ""
    bug_type: str = ""  # heap-buffer-overflow, stack-buffer-overflow, heap-use-after-free, double-free, etc.
    bug_category: str = ""  # heap, stack, other
    access_type: str = ""  # READ or WRITE
    access_size: int = 0
    access_address: int = 0
    crash_trace: list = field(default_factory=list)
    heap_info: Optional[HeapInfo] = None
    stack_info: Optional[StackInfo] = None
    thread_id: int = 0
    signal: str = ""
    is_segv: bool = False
    is_null_deref: bool = False
    shadow_byte_legend: dict = field(default_factory=dict)
    shadow_bytes: str = ""
    summary_line: str = ""
    address_bits: int = 64
    is_kasan: bool = False
    is_gdb: bool = False
    registers: dict = field(default_factory=dict)  # GDB register state

    def to_dict(self):
        return {
            "bug_type": self.bug_type,
            "bug_category": self.bug_category,
            "access_type": self.access_type,
            "access_size": self.access_size,
            "access_address": hex(self.access_address) if self.access_address else "0x0",
            "crash_trace": [f.to_dict() for f in self.crash_trace],
            "heap_info": self.heap_info.to_dict() if self.heap_info else None,
            "stack_info": self.stack_info.to_dict() if self.stack_info else None,
            "thread_id": self.thread_id,
            "signal": self.signal,
            "is_null_deref": self.is_null_deref,
            "summary_line": self.summary_line,
            "address_bits": self.address_bits,
            "is_kasan": self.is_kasan,
            "is_gdb": self.is_gdb,
            "registers": self.registers,
        }


# Map raw ASAN error strings to normalized bug types
BUG_TYPE_MAP = {
    "heap-buffer-overflow": "heap-buffer-overflow",
    "heap-buffer-underflow": "heap-buffer-underflow",
    "stack-buffer-overflow": "stack-buffer-overflow",
    "stack-buffer-underflow": "stack-buffer-underflow",
    "heap-use-after-free": "heap-use-after-free",
    "double-free": "double-free",
    "stack-use-after-return": "stack-use-after-return",
    "stack-use-after-scope": "stack-use-after-scope",
    "global-buffer-overflow": "global-buffer-overflow",
    "use-after-poison": "use-after-poison",
    "container-overflow": "container-overflow",
    "stack-overflow": "stack-overflow",
    "dynamic-stack-buffer-overflow": "stack-buffer-overflow",
    "attempting free on address which was not malloc()-ed": "invalid-free",
    "attempting double-free": "double-free",
    "alloc-dealloc-mismatch": "alloc-dealloc-mismatch",
    "new-delete-type-mismatch": "new-delete-type-mismatch",
}

CATEGORY_MAP = {
    "heap-buffer-overflow": "heap",
    "heap-buffer-underflow": "heap",
    "stack-buffer-overflow": "stack",
    "stack-buffer-underflow": "stack",
    "heap-use-after-free": "heap",
    "double-free": "heap",
    "stack-use-after-return": "stack",
    "stack-use-after-scope": "stack",
    "global-buffer-overflow": "other",
    "use-after-poison": "other",
    "container-overflow": "heap",
    "stack-overflow": "stack",
    "invalid-free": "heap",
    "alloc-dealloc-mismatch": "heap",
    "new-delete-type-mismatch": "heap",
    "null-deref": "other",
    "segv": "other",
}


# Pre-compiled regex patterns
_RE_FRAME_START = re.compile(r"^\s*#\d+")
_RE_FRAME_MOD = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+\((\S+)\+(0x[0-9a-fA-F]+)\)")
_RE_FRAME_FULL = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(.+?)\s+(\S+:\d+(?::\d+)?)\s*$")
_RE_FRAME_NOSRC = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)")
_RE_FRAME_BARE = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)")
_RE_ERROR = re.compile(r"ERROR:\s*AddressSanitizer:\s*(.+?)(?:\s+on\s+|$)")
_RE_SEGV = re.compile(r"ERROR:\s*AddressSanitizer:\s*SEGV\s+on\s+unknown\s+address\s+(0x[0-9a-fA-F]+)")
_RE_SEGV_ACCESS = re.compile(r"The signal is caused by a (READ|WRITE) memory access")
_RE_ACCESS = re.compile(r"(READ|WRITE)\s+of\s+size\s+(\d+)\s+at\s+(0x[0-9a-fA-F]+)")
_RE_THREAD = re.compile(r"thread\s+T(\d+)")
_RE_LOCATION = re.compile(r"(0x[0-9a-fA-F]+)\s+is\s+located\s+(\d+)\s+bytes?\s+to\s+the\s+(right|left)\s+of\s+(\d+)-byte\s+region\s+\[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)")
_RE_LOCATION_INSIDE = re.compile(r"(0x[0-9a-fA-F]+)\s+is\s+located\s+(\d+)\s+bytes?\s+inside\s+of\s+(\d+)-byte\s+region\s+\[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)")
_RE_STACK_VAR_DETAIL = re.compile(r"is\s+located\s+(\d+)\s+bytes?\s+to\s+the\s+(right|left)\s+.*?'(\w+)'\s*.*?of\s+size\s+(\d+)")
_RE_SUMMARY = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(.+)")
_RE_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_RE_SHADOW_LINE = re.compile(r"^\s*0x")
_RE_KASAN_BUG = re.compile(r"BUG:\s*KASAN:\s*(\S+)\s+in\s+(\S+)")
_RE_KASAN_ACCESS = re.compile(r"(Read|Write)\s+of\s+size\s+(\d+)\s+at\s+addr\s+([\da-fA-Fx]+)")
_RE_KASAN_ACCESS2 = re.compile(r"(Read|Write)\s+of\s+size\s+(\d+)")
_RE_KASAN_ADDR = re.compile(r"at\s+addr\s+([\da-fA-Fx]+)")
_RE_KASAN_SUMMARY = re.compile(r"SUMMARY:\s*KASAN:\s*(.+)")
_RE_KASAN_FUNC_OFFSET = re.compile(r'\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+$')
_RE_KASAN_TRACE_LINE = re.compile(r'^\s*\??\s*(\S+)\+(0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+)')
_RE_DMESG_TIMESTAMP = re.compile(r'^\s*\[\s*[\d.]+\]\s*')
_RE_MSAN_WARN = re.compile(r"WARNING:\s*MemorySanitizer:\s*use-of-uninitialized-value")
_RE_MSAN_ORIGIN = re.compile(r"Uninitialized value was created by.*?(heap|stack)\s+allocation")
_RE_MSAN_SUMMARY = re.compile(r"SUMMARY:\s*MemorySanitizer:\s*(.+)")
_RE_UBSAN_ERROR = re.compile(r"(\S+:\d+:\d+):\s+runtime error:\s+(.+)")
_RE_GDB_SIGNAL = re.compile(r"Program received signal (\w+)")
_RE_GDB_REG = re.compile(r"^(\w+)\s+(0x[0-9a-fA-F]+)\b")
_RE_GDB_FRAME = re.compile(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(.+?)(?:\s+\(|$)")
_RE_GDB_FRAME2 = re.compile(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+\?\?\s*\(\)")
_RE_GDB_SRC = re.compile(r"at\s+(\S+):(\d+)")
_RE_FRAME_ZERO = re.compile(r"^\s*#0")
_RE_READ_WRITE_SIZE = re.compile(r"(READ|WRITE)\s+of\s+size")


def _parse_hex(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 16)


def _parse_stack_trace(lines: list[str], start: int) -> tuple[list[StackFrame], int]:
    """Parse a stack trace starting at `start`. Returns (frames, next_line_index)."""
    frames = []
    i = start

    while i < len(lines):
        line = lines[i]
        if not _RE_FRAME_START.match(line):
            break

        f = StackFrame(frame_num=0, address=0)

        m = _RE_FRAME_MOD.match(line)
        if m:
            f.frame_num = int(m.group(1))
            f.address = _parse_hex(m.group(2))
            f.module = m.group(3)
            frames.append(f)
            i += 1
            continue

        # Try full pattern with source info
        m = _RE_FRAME_FULL.match(line)
        if m:
            f.frame_num = int(m.group(1))
            f.address = _parse_hex(m.group(2))
            f.function = m.group(3).strip()
            loc = m.group(4)
            parts = loc.rsplit(":", 2)
            f.source_file = parts[0]
            if len(parts) > 1:
                try:
                    f.line = int(parts[1])
                except ValueError:
                    pass
            if len(parts) > 2:
                try:
                    f.column = int(parts[2])
                except ValueError:
                    pass
            frames.append(f)
            i += 1
            continue

        # Try without source
        m = _RE_FRAME_NOSRC.match(line)
        if m:
            f.frame_num = int(m.group(1))
            f.address = _parse_hex(m.group(2))
            f.function = m.group(3)
            frames.append(f)
            i += 1
            continue

        # Bare frame
        m = _RE_FRAME_BARE.match(line)
        if m:
            f.frame_num = int(m.group(1))
            f.address = _parse_hex(m.group(2))
            frames.append(f)
            i += 1
            continue

        break

    return frames, i


def parse_asan_log(log: str) -> AsanReport:
    """Parse an ASAN log string into an AsanReport."""
    report = AsanReport(raw_log=log)
    lines = log.splitlines()

    # Detect address size
    for line in lines:
        addrs = _RE_HEX_ADDR.findall(line)
        for a in addrs:
            if len(a) > 10:  # more than 0x + 8 hex digits
                report.address_bits = 64
                break
            elif len(a) > 2:
                report.address_bits = 32

    # Detect sanitizer type (ASAN, MSAN, UBSAN, KASAN, GDB)
    if "MemorySanitizer" in log:
        return _parse_msan_log(log, report)
    if "runtime error:" in log and "AddressSanitizer" not in log:
        return _parse_ubsan_log(log, report)
    if "BUG: KASAN:" in log:
        return _parse_kasan_log(log, report)
    if "Program received signal" in log or ("SIGSEGV" in log and "#0" in log and "rip" in log.lower()):
        return _parse_gdb_log(log, report)

    # Use pre-compiled patterns

    for i, line in enumerate(lines):
        # Main error line
        m = _RE_SEGV.search(line)
        if m:
            addr = _parse_hex(m.group(1))
            report.access_address = addr
            report.is_segv = True
            if addr < 0x10000:
                report.bug_type = "null-deref"
                report.is_null_deref = True
            else:
                report.bug_type = "segv"
            report.bug_category = "other"
            continue

        # SEGV access type from "The signal is caused by a READ/WRITE memory access"
        m = _RE_SEGV_ACCESS.search(line)
        if m:
            report.access_type = m.group(1)

        m = _RE_ERROR.search(line)
        if m and not report.bug_type:
            raw_type = m.group(1).strip()
            for key, val in BUG_TYPE_MAP.items():
                if key in raw_type:
                    report.bug_type = val
                    report.bug_category = CATEGORY_MAP.get(val, "other")
                    break
            if not report.bug_type:
                report.bug_type = raw_type
                report.bug_category = "other"

        # Access info
        m = _RE_ACCESS.search(line)
        if m:
            report.access_type = m.group(1)
            report.access_size = int(m.group(2))
            report.access_address = _parse_hex(m.group(3))

        # Thread
        m = _RE_THREAD.search(line)
        if m and report.thread_id == 0:
            report.thread_id = int(m.group(1))

        # Location relative to heap region
        m = _RE_LOCATION.search(line)
        if m:
            if report.heap_info is None:
                report.heap_info = HeapInfo()
            report.heap_info.address = _parse_hex(m.group(1))
            report.heap_info.offset = int(m.group(2))
            report.heap_info.direction = m.group(3)
            report.heap_info.region_size = int(m.group(4))

            # If direction is "left", it's an underflow
            if m.group(3) == "left" and "underflow" not in report.bug_type:
                if report.bug_type == "heap-buffer-overflow":
                    report.bug_type = "heap-buffer-underflow"

        m = _RE_LOCATION_INSIDE.search(line)
        if m:
            if report.heap_info is None:
                report.heap_info = HeapInfo()
            report.heap_info.address = _parse_hex(m.group(1))
            report.heap_info.offset = int(m.group(2))
            report.heap_info.direction = "inside"
            report.heap_info.region_size = int(m.group(3))

        # Stack variable info
        m = _RE_STACK_VAR_DETAIL.search(line)
        if m:
            if report.stack_info is None:
                report.stack_info = StackInfo()
            report.stack_info.offset = int(m.group(1))
            report.stack_info.direction = m.group(2)
            report.stack_info.variable_name = m.group(3)
            report.stack_info.variable_size = int(m.group(4))

        # Summary
        m = _RE_SUMMARY.search(line)
        if m:
            report.summary_line = m.group(1).strip()

    # Parse stack traces
    i = 0
    while i < len(lines):
        line = lines[i]

        # Crash/access trace
        if _RE_READ_WRITE_SIZE.search(line) or (
            "ERROR: AddressSanitizer" in line and not report.crash_trace
        ):
            # Next lines should be the stack trace
            j = i + 1
            while j < len(lines) and not _RE_FRAME_ZERO.match(lines[j]):
                j += 1
                if j - i > 3:
                    break
            if j < len(lines) and _RE_FRAME_ZERO.match(lines[j]):
                frames, j = _parse_stack_trace(lines, j)
                if frames and not report.crash_trace:
                    report.crash_trace = frames
                i = j
                continue

        # Alloc/free traces for heap bugs
        if report.heap_info is not None:
            if "freed by thread" in line or "previously freed by" in line.lower():
                m = _RE_THREAD.search(line)
                if m:
                    report.heap_info.free_thread = int(m.group(1))
                j = i + 1
                while j < len(lines) and not _RE_FRAME_ZERO.match(lines[j]):
                    j += 1
                    if j - i > 3:
                        break
                if j < len(lines) and _RE_FRAME_ZERO.match(lines[j]):
                    frames, j = _parse_stack_trace(lines, j)
                    report.heap_info.free_trace = frames
                    report.heap_info.chunk_state = "freed"
                    i = j
                    continue

            if (
                "allocated by thread" in line
                or "previously allocated by" in line.lower()
            ):
                m = _RE_THREAD.search(line)
                if m:
                    report.heap_info.alloc_thread = int(m.group(1))
                j = i + 1
                while j < len(lines) and not _RE_FRAME_ZERO.match(lines[j]):
                    j += 1
                    if j - i > 3:
                        break
                if j < len(lines) and _RE_FRAME_ZERO.match(lines[j]):
                    frames, j = _parse_stack_trace(lines, j)
                    report.heap_info.alloc_trace = frames
                    i = j
                    continue

        i += 1

    # Parse shadow bytes
    shadow_lines = []
    in_shadow = False
    for line in lines:
        if "Shadow bytes around" in line:
            in_shadow = True
            continue
        if in_shadow:
            if _RE_SHADOW_LINE.match(line) or "=>" in line:
                shadow_lines.append(line)
            else:
                in_shadow = False
    report.shadow_bytes = "\n".join(shadow_lines)

    return report


def _parse_msan_log(log: str, report: AsanReport) -> AsanReport:
    """Parse MemorySanitizer output."""
    lines = log.splitlines()
    report.bug_type = "use-of-uninitialized-value"
    report.bug_category = "other"

    for i, line in enumerate(lines):
        m = _RE_MSAN_WARN.search(line)
        if m:
            # Parse stack trace following
            j = i + 1
            while j < len(lines) and not _RE_FRAME_ZERO.match(lines[j]):
                j += 1
                if j - i > 3:
                    break
            if j < len(lines) and _RE_FRAME_ZERO.match(lines[j]):
                frames, _ = _parse_stack_trace(lines, j)
                if frames:
                    report.crash_trace = frames

        m = _RE_MSAN_ORIGIN.search(line)
        if m:
            report.bug_category = m.group(1)

        m = _RE_MSAN_SUMMARY.search(line)
        if m:
            report.summary_line = m.group(1).strip()

    return report


def _parse_ubsan_log(log: str, report: AsanReport) -> AsanReport:
    """Parse UndefinedBehaviorSanitizer output."""
    lines = log.splitlines()
    report.bug_category = "other"

    for line in lines:
        m = _RE_UBSAN_ERROR.search(line)
        if m:
            loc = m.group(1)
            error_msg = m.group(2)
            report.summary_line = error_msg

            # Classify
            if "signed integer overflow" in error_msg or "unsigned integer overflow" in error_msg:
                report.bug_type = "integer-overflow"
            elif "shift" in error_msg:
                report.bug_type = "invalid-shift"
            elif "division by zero" in error_msg:
                report.bug_type = "division-by-zero"
            elif "null pointer" in error_msg:
                report.bug_type = "null-deref"
                report.is_null_deref = True
            elif "out of bounds" in error_msg:
                report.bug_type = "array-out-of-bounds"
            elif "alignment" in error_msg:
                report.bug_type = "misaligned-access"
            else:
                report.bug_type = "undefined-behavior"

            # Parse location
            parts = loc.rsplit(":", 2)
            if len(parts) >= 2:
                frame = StackFrame(frame_num=0, address=0, source_file=parts[0])
                try:
                    frame.line = int(parts[1])
                except ValueError:
                    pass
                report.crash_trace = [frame]
            break

    return report


def _parse_kasan_log(log: str, report: AsanReport) -> AsanReport:
    """Parse Kernel AddressSanitizer (KASAN) output."""
    lines = log.splitlines()
    report.is_kasan = True

    # KASAN bug type mapping (kernel-specific types)
    kasan_type_map = {
        "slab-out-of-bounds": "heap-buffer-overflow",
        "slab-use-after-free": "heap-use-after-free",
        "use-after-free": "heap-use-after-free",
        "double-free": "double-free",
        "null-ptr-deref": "null-deref",
        "out-of-bounds": "heap-buffer-overflow",
        "global-out-of-bounds": "global-buffer-overflow",
        "stack-out-of-bounds": "stack-buffer-overflow",
    }

    # Strip dmesg timestamps from all lines for easier parsing
    clean_lines = [re.sub(r'^\s*\[\s*[\d.]+\]\s*', '', l) for l in lines]

    for i, line in enumerate(clean_lines):
        m = _RE_KASAN_BUG.search(line)
        if m:
            raw_type = m.group(1)
            func = m.group(2)
            # Strip offset from function name (e.g., log_replay+0x40c4/0x7870)
            func_clean = re.sub(r'\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+$', '', func)

            # Map KASAN type
            for key, val in kasan_type_map.items():
                if key in raw_type:
                    report.bug_type = val
                    break
            if not report.bug_type:
                for key, val in BUG_TYPE_MAP.items():
                    if key in raw_type:
                        report.bug_type = val
                        break
            if not report.bug_type:
                report.bug_type = raw_type
            report.bug_category = CATEGORY_MAP.get(report.bug_type, "other")

        m = re.search(r"(Read|Write)\s+of\s+size\s+(\d+)\s+at\s+addr\s+([\da-fA-Fx]+)", line)
        if m:
            report.access_type = m.group(1).upper()
            report.access_size = int(m.group(2))
            report.access_address = _parse_hex(m.group(3))
        elif not report.access_type:
            m = re.search(r"(Read|Write)\s+of\s+size\s+(\d+)", line)
            if m:
                report.access_type = m.group(1).upper()
                report.access_size = int(m.group(2))
            m2 = re.search(r"at\s+addr\s+([\da-fA-Fx]+)", line)
            if m2:
                report.access_address = _parse_hex(m2.group(1))

        m = re.search(r"SUMMARY:\s*KASAN:\s*(.+)", line)
        if m:
            report.summary_line = m.group(1).strip()

    # Parse Call Trace (kernel format)
    report.crash_trace = _parse_kasan_call_trace(lines)

    # Parse heap region info — may span multiple lines in KASAN
    full_text = "\n".join(lines)
    # Normalize multi-line region info
    full_text_single = re.sub(r'\n\s+', ' ', full_text)
    m = re.search(r"located\s+(\d+)\s+bytes?\s+to\s+the\s+(right|left)\s+of.*?(\d+)-byte\s+region\s+\[([\da-fA-Fx]+),\s*([\da-fA-Fx]+)\)", full_text_single)
    if m:
        if report.heap_info is None:
            report.heap_info = HeapInfo()
        report.heap_info.offset = int(m.group(1))
        report.heap_info.direction = m.group(2)
        report.heap_info.region_size = int(m.group(3))
        report.heap_info.address = _parse_hex(m.group(4))
    m = re.search(r"located\s+(\d+)\s+bytes?\s+inside\s+of\s+(\d+)-byte\s+region\s+\[([\da-fA-Fx]+),\s*([\da-fA-Fx]+)\)", full_text_single)
    if m:
        if report.heap_info is None:
            report.heap_info = HeapInfo()
        report.heap_info.offset = int(m.group(1))
        report.heap_info.direction = "inside"
        report.heap_info.region_size = int(m.group(2))
        report.heap_info.address = _parse_hex(m.group(3))

    # Parse "Allocated by task" trace
    _parse_kasan_alloc_free_traces(lines, report)

    # Parse shadow bytes
    shadow_lines = []
    in_shadow = False
    for line in lines:
        if "Memory state around" in line:
            in_shadow = True
            continue
        if in_shadow:
            if re.match(r"^\s*[\da-fA-Fx]+:", line) or ">" in line:
                shadow_lines.append(line)
            elif line.strip() == "" or "=" in line:
                in_shadow = False
    report.shadow_bytes = "\n".join(shadow_lines)

    return report


def _parse_kasan_call_trace(lines: list[str]) -> list[StackFrame]:
    """Parse kernel Call Trace format into StackFrame list."""
    frames = []
    in_trace = False
    frame_num = 0

    for line in lines:
        if "Call Trace:" in line:
            in_trace = True
            frame_num = 0
            frames = []
            continue
        if in_trace:
            # Strip dmesg timestamp prefix like "[  123.456789] "
            stripped = re.sub(r'^\s*\[\s*[\d.]+\]\s*', '', line).strip()
            if stripped in ("<TASK>", "</TASK>", "<IRQ>", "</IRQ>", ""):
                continue
            # Parse kernel trace line: function+0xoffset/0xsize
            m = re.match(r'^\s*\??\s*(\S+)\+(0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+)', stripped)
            if m:
                func = m.group(1)
                offset = _parse_hex(m.group(2))
                # Skip KASAN internals for the main trace
                if any(x in func for x in ('kasan_', '__asan_', 'print_report', 'dump_stack', '__virt_addr_valid', 'kasan_complete')):
                    continue
                f = StackFrame(
                    frame_num=frame_num,
                    address=offset,
                    function=func,
                    module="kernel",
                )
                frames.append(f)
                frame_num += 1
                continue
            # If line doesn't match trace format, end of trace
            if not re.match(r'^\s', line) and stripped and not stripped.startswith('?'):
                in_trace = False

    return frames


def _parse_kasan_alloc_free_traces(lines: list[str], report: AsanReport):
    """Parse 'Allocated by task' and 'Freed by task' sections in KASAN output."""
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.search(r'Allocated by task', line):
            if report.heap_info is None:
                report.heap_info = HeapInfo()
            frames = _parse_kasan_subtrace(lines, i + 1)
            report.heap_info.alloc_trace = frames
        elif re.search(r'Freed by task', line):
            if report.heap_info is None:
                report.heap_info = HeapInfo()
            frames = _parse_kasan_subtrace(lines, i + 1)
            report.heap_info.free_trace = frames
            report.heap_info.chunk_state = "freed"
        i += 1


def _parse_kasan_subtrace(lines: list[str], start: int) -> list[StackFrame]:
    """Parse a KASAN sub-trace (allocation/free) starting at given line."""
    frames = []
    frame_num = 0
    for i in range(start, min(start + 30, len(lines))):
        stripped = lines[i].strip()
        if not stripped:
            break
        m = re.match(r'^(\S+)\+(0x[0-9a-fA-F]+)/(0x[0-9a-fA-F]+)', stripped)
        if m:
            func = m.group(1)
            offset = _parse_hex(m.group(2))
            f = StackFrame(frame_num=frame_num, address=offset, function=func, module="kernel")
            frames.append(f)
            frame_num += 1
        elif stripped.startswith("=") or stripped.startswith("The "):
            break
    return frames


def _parse_gdb_log(log: str, report: AsanReport) -> AsanReport:
    """Parse a GDB crash log with register state and backtrace."""
    report.is_gdb = True
    lines = log.splitlines()

    # Parse signal
    for line in lines:
        m = re.search(r"Program received signal (\w+)", line)
        if m:
            report.signal = m.group(1)
            report.is_segv = "SEGV" in report.signal
            break

    # Parse registers
    reg_re = re.compile(r"^(\w+)\s+(0x[0-9a-fA-F]+)\b")
    for line in lines:
        m = reg_re.match(line.strip())
        if m:
            report.registers[m.group(1)] = _parse_hex(m.group(2))

    # Detect crash address from RIP
    if "rip" in report.registers:
        report.access_address = report.registers["rip"]

    # Parse GDB backtrace frames: #N 0xADDR in FUNC () ...
    frame_re = re.compile(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(.+?)(?:\s+\(|$)")
    frame_re2 = re.compile(r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+\?\?\s*\(\)")
    for line in lines:
        line = line.strip()
        m = frame_re.match(line)
        if not m:
            m = frame_re2.match(line)
        if m:
            addr = _parse_hex(m.group(2))
            func = m.group(3).strip() if m.lastindex >= 3 else ""
            if func == "??" or func == "??()":
                func = ""
            # Extract source file if present: at file.c:line
            src_file = ""
            src_line = 0
            sm = re.search(r"at\s+(\S+):(\d+)", line)
            if sm:
                src_file = sm.group(1)
                src_line = int(sm.group(2))
            f = StackFrame(
                frame_num=int(m.group(1)),
                address=addr,
                function=func,
                source_file=src_file,
                line=src_line,
            )
            report.crash_trace.append(f)

    # Determine bug type from register patterns
    # Check for stack buffer overflow: controlled RBP/RIP + pattern on stack
    controlled_regs = []
    pattern_vals = {0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
                    0x4444444444444444, 0x4545454545454545, 0x4646464646464646,
                    0x4141414141414141 & 0xFFFFFFFF}  # 32-bit too
    for reg, val in report.registers.items():
        if val in pattern_vals or (val & 0xFFFFFFFF00000000 == 0 and (val & 0xFFFFFFFF) in
                                   {0x41414141, 0x42424242, 0x43434343, 0x44444444}):
            controlled_regs.append(reg)

    # Count how many stack frames are controlled (pattern addresses)
    controlled_frames = sum(1 for f in report.crash_trace
                           if f.address in pattern_vals or
                           (f.address & 0xFFFFFFFF) in {0x41414141, 0x42424242, 0x43434343, 0x44444444})

    if "rbp" in controlled_regs or "rsp" in controlled_regs or controlled_frames > 3:
        report.bug_type = "stack-buffer-overflow"
        report.bug_category = "stack"
        report.access_type = "WRITE"
        # Estimate overflow size from controlled frames
        report.access_size = controlled_frames * 8  # each frame = 8 bytes on stack
        report.stack_info = StackInfo(
            variable_name="return_address",
            variable_size=controlled_frames * 8,
            offset=controlled_frames * 8,
            direction="right",
        )
        report.summary_line = (
            f"Stack Buffer Overflow — {len(controlled_regs)} registers controlled "
            f"({', '.join(controlled_regs)}), {controlled_frames} stack frames smashed"
        )
    elif report.is_segv:
        # Check if it's a null deref
        if report.access_address and report.access_address < 0x10000:
            report.bug_type = "null-dereference"
            report.bug_category = "other"
            report.is_null_deref = True
            report.access_type = "READ"
            report.summary_line = f"NULL pointer dereference at {hex(report.access_address)}"
        else:
            report.bug_type = "SEGV"
            report.bug_category = "other"
            report.access_type = "UNKNOWN"
            report.summary_line = f"Segmentation fault at {hex(report.access_address)}"
    else:
        report.bug_type = report.signal.lower() if report.signal else "unknown"
        report.bug_category = "other"
        report.summary_line = f"Crash: {report.signal}"

    return report

