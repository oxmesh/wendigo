"""Generate visualization data structures for the web UI SVG diagrams."""

from .parser import AsanReport


def generate_visualization(report: AsanReport, analysis: dict) -> dict:
    """
    Return a JSON-serializable dict describing the diagram to render.
    The JS frontend (diagrams.js) interprets this.
    """
    bt = report.bug_type
    viz = {
        "diagram_type": _classify_diagram(bt),
        "bug_type": bt,
        "access_type": report.access_type,
        "access_size": report.access_size,
        "access_address": hex(report.access_address) if report.access_address else "0x0",
        "address_bits": report.address_bits,
        "severity": analysis["severity"],
        "elements": [],
    }

    if bt in ("heap-buffer-overflow", "heap-buffer-underflow"):
        viz["elements"] = _heap_oob(report)
    elif bt == "heap-use-after-free":
        viz["elements"] = _uaf(report)
    elif bt == "double-free":
        viz["elements"] = _double_free(report)
    elif bt in ("stack-buffer-overflow", "stack-buffer-underflow"):
        viz["elements"] = _stack_overflow(report)
    elif bt == "stack-use-after-return":
        viz["elements"] = _stack_use_after_return(report)
    elif report.is_null_deref:
        viz["elements"] = _null_deref(report)
    elif report.is_segv:
        viz["elements"] = _segv(report)
    else:
        viz["elements"] = _generic(report)

    return viz


_SKIP_FUNCS = {"__interceptor_memcpy", "__interceptor_memmove", "__interceptor_memset",
               "__interceptor_strcpy", "__interceptor_strncpy", "__asan_memcpy",
               "__asan_memmove", "__asan_memset", "malloc", "calloc", "realloc",
               "free", "__interceptor_malloc", "__interceptor_free",
               "__interceptor_calloc", "__interceptor_realloc", "operator new",
               "operator delete"}


def _first_real_func(trace):
    """Return the first non-sanitizer/libc function name from a stack trace."""
    if not trace:
        return ""
    for frame in trace:
        if frame.function and frame.function not in _SKIP_FUNCS:
            return frame.function
    return trace[0].function if trace else ""


def _classify_diagram(bt: str) -> str:
    mapping = {
        "heap-buffer-overflow": "heap_oob",
        "heap-buffer-underflow": "heap_oob",
        "heap-use-after-free": "uaf_timeline",
        "double-free": "double_free",
        "stack-buffer-overflow": "stack_layout",
        "stack-buffer-underflow": "stack_layout",
        "stack-use-after-return": "stack_layout",
        "stack-use-after-scope": "stack_layout",
        "null-deref": "memory_map",
        "segv": "memory_map",
    }
    return mapping.get(bt, "generic")


def _heap_oob(report: AsanReport) -> list:
    """Heap OOB: linear memory layout with overflow visualization."""
    hi = report.heap_info
    if not hi:
        return _generic(report)

    region_size = hi.region_size or 64
    offset = hi.offset or 0
    direction = hi.direction or "right"
    is_write = report.access_type == "WRITE"
    access_size = report.access_size or 1

    # Calculate the actual overflow extent
    if direction == "right":
        overflow_bytes = offset + access_size
    else:
        overflow_bytes = offset + access_size

    # Compute addresses if available
    region_start = 0
    region_end = 0
    access_addr = 0
    if hi.address:
        if direction == "right":
            region_end = hi.address - offset if isinstance(hi.address, int) else 0
            region_start = region_end - region_size
        elif direction == "inside":
            region_start = (hi.address - offset) if isinstance(hi.address, int) else 0
            region_end = region_start + region_size

    return [{
        "type": "heap_linear",
        "region_size": region_size,
        "access_size": access_size,
        "access_type": report.access_type,
        "offset": offset,
        "direction": direction,
        "overflow_bytes": overflow_bytes,
        "region_start_addr": hex(region_start) if region_start else "",
        "region_end_addr": hex(region_end) if region_end else "",
        "access_addr": hex(report.access_address) if report.access_address else "",
        "alloc_func": _first_real_func(hi.alloc_trace),
        "crash_func": _first_real_func(report.crash_trace),
        "is_write": is_write,
        "severity": "CRITICAL" if is_write and access_size >= 8 else ("HIGH" if is_write else "MEDIUM"),
    }]


def _uaf(report: AsanReport) -> list:
    """UAF timeline: alloc → free → reuse."""
    hi = report.heap_info
    region_size = hi.region_size if hi else 64

    alloc_func = ""
    free_func = ""
    reuse_func = ""

    if hi and hi.alloc_trace:
        alloc_func = _first_real_func(hi.alloc_trace)
    if hi and hi.free_trace:
        free_func = _first_real_func(hi.free_trace)
    if report.crash_trace:
        reuse_func = _first_real_func(report.crash_trace)

    # Get source locations for each trace
    def _frame_loc(trace):
        if not trace:
            return ""
        for f in trace:
            if f.source_file:
                return f"{f.source_file}:{f.line}"
        return ""

    return [
        {
            "type": "timeline_event",
            "order": 1,
            "event": "malloc",
            "label": f"Allocated {region_size}B",
            "function": alloc_func,
            "source": _frame_loc(hi.alloc_trace if hi else None),
            "state": "allocated",
            "color": "#44cc44",
        },
        {
            "type": "timeline_event",
            "order": 2,
            "event": "free",
            "label": f"Freed {region_size}B",
            "function": free_func,
            "source": _frame_loc(hi.free_trace if hi else None),
            "state": "freed",
            "color": "#ff4444",
        },
        {
            "type": "timeline_event",
            "order": 3,
            "event": "reuse",
            "label": f"{'Write' if report.access_type == 'WRITE' else 'Read'} after free ({report.access_size}B)",
            "function": reuse_func,
            "source": _frame_loc(report.crash_trace),
            "state": "dangling",
            "color": "#ffaa00",
        },
        {
            "type": "chunk",
            "label": f"Freed Region ({region_size}B)",
            "size": region_size,
            "state": "freed",
            "offset": hi.offset if hi else 0,
            "access_size": report.access_size,
            "access_type": report.access_type,
            "access_addr": hex(report.access_address) if report.access_address else "",
        },
    ]


def _double_free(report: AsanReport) -> list:
    hi = report.heap_info
    region_size = hi.region_size if hi else 64

    free1_func = ""
    free2_func = ""
    if hi and hi.free_trace:
        free1_func = _first_real_func(hi.free_trace)
    if report.crash_trace:
        free2_func = _first_real_func(report.crash_trace)

    return [
        {
            "type": "timeline_event",
            "order": 1,
            "event": "malloc",
            "label": f"Allocated {region_size}B",
            "state": "allocated",
            "color": "#44cc44",
        },
        {
            "type": "timeline_event",
            "order": 2,
            "event": "free",
            "label": "First free()",
            "function": free1_func,
            "state": "freed",
            "color": "#ff4444",
        },
        {
            "type": "timeline_event",
            "order": 3,
            "event": "free",
            "label": "Second free() ← CRASH",
            "function": free2_func,
            "state": "double_free",
            "color": "#ff0000",
        },
        {
            "type": "freelist",
            "label": "Corrupted Freelist",
            "chunk_size": region_size,
            "entries": [
                {"addr": hex(report.access_address) if report.access_address else "chunk_A", "state": "freed", "label": "1st free"},
                {"addr": "other_chunk", "state": "normal", "label": "..."},
                {"addr": hex(report.access_address) if report.access_address else "chunk_A", "state": "duplicate", "highlight": True, "label": "2nd free ⚠"},
            ],
        },
    ]


def _stack_overflow(report: AsanReport) -> list:
    si = report.stack_info
    var_name = si.variable_name if si else "buffer"
    var_size = si.variable_size if si else 64
    offset = si.offset if si else 0
    direction = si.direction if si else "right"
    is_write = report.access_type == "WRITE"

    # Build stack frame layout (high → low addresses)
    # offset = bytes past the buffer boundary; access_size = total write size
    # For right overflow: overflow_extent = offset + access_size (total bytes past buffer end)
    overflow_extent = offset + (report.access_size or 0) if direction == "right" else 0
    elements = [
        {"type": "stack_slot", "label": "Return Address", "size": 8, "smashed": direction == "right" and overflow_extent > 16 and is_write},
        {"type": "stack_slot", "label": "Saved RBP", "size": 8, "smashed": direction == "right" and overflow_extent > 8 and is_write},
        {"type": "stack_slot", "label": "Canary", "size": 8, "smashed": direction == "right" and overflow_extent > 0 and is_write},
        {"type": "stack_slot", "label": f"{var_name} [{var_size}B]", "size": var_size, "is_target": True},
        {"type": "stack_slot", "label": "Other locals", "size": 32, "smashed": direction == "left" and is_write},
    ]

    elements.append({
        "type": "arrow",
        "direction": direction,
        "distance": offset,
        "access_size": report.access_size,
        "is_write": is_write,
        "label": f"{'WRITE' if is_write else 'READ'} {report.access_size}B, {offset}B {direction} of '{var_name}'",
    })

    return elements


def _stack_use_after_return(report: AsanReport) -> list:
    func = report.crash_trace[0].function if report.crash_trace else "unknown"
    return [
        {
            "type": "timeline_event",
            "order": 1,
            "event": "call",
            "label": f"Function {func} called",
            "state": "allocated",
            "color": "#44cc44",
        },
        {
            "type": "timeline_event",
            "order": 2,
            "event": "return",
            "label": f"Function {func} returned",
            "state": "freed",
            "color": "#ff4444",
        },
        {
            "type": "timeline_event",
            "order": 3,
            "event": "use",
            "label": "Dangling pointer used",
            "state": "dangling",
            "color": "#ffaa00",
        },
    ]


def _null_deref(report: AsanReport) -> list:
    access_type = report.access_type or "READ"
    is_write = access_type == "WRITE"
    return [
        {
            "type": "memory_map",
            "is_null_deref": True,
            "is_write": is_write,
            "crash_func": _first_real_func(report.crash_trace),
            "regions": [
                {"start": "0x0", "end": "0xfff", "label": "NULL Page (unmapped)", "state": "unmapped", "icon": "🚫"},
                {"start": hex(report.access_address), "label": f"{access_type} @ {hex(report.access_address)}", "state": "crash", "access_type": access_type},
                {"start": "0x1000", "end": "0x400000", "label": "Code (.text)", "state": "mapped", "icon": "📄"},
                {"start": "0x400000", "end": "0x600000", "label": "Heap", "state": "mapped", "icon": "📦"},
                {"start": "0x7fff0000", "end": "0x7fffffff", "label": "Stack", "state": "mapped", "icon": "📚"},
            ],
        }
    ]


def _segv(report: AsanReport) -> list:
    return [
        {
            "type": "memory_map",
            "regions": [
                {"start": "0x0", "end": "0x1000", "label": "Guard Page", "state": "unmapped"},
                {"start": hex(report.access_address), "label": f"SEGV @ {hex(report.access_address)}", "state": "crash", "access_type": report.access_type},
            ],
        }
    ]


def _generic(report: AsanReport) -> list:
    return [
        {
            "type": "info_box",
            "title": report.bug_type or "Unknown",
            "details": {
                "access_type": report.access_type,
                "access_size": report.access_size,
                "address": hex(report.access_address) if report.access_address else "N/A",
            },
        }
    ]

