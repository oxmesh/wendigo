"""
Exploitability analysis — scores crashes like an exploit developer would.

Scoring philosophy:
  - A vulnerability's exploitability depends on the PRIMITIVE it gives you
  - WRITE primitives are king: arbitrary write → code execution
  - The question is always: "How many steps from this bug to rce/lpe?"
  - 1 step (controlled RIP, GOT overwrite) → CRITICAL
  - 2-3 steps (need info leak first, or heap feng shui) → HIGH
  - Needs complex chain or only gives info leak → MEDIUM
  - DoS only or nearly unexploitable → LOW/NOT EXPLOITABLE
"""

import re
from .parser import AsanReport


SEVERITY_ORDER = ["NOT EXPLOITABLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# glibc heap metadata size (prev_size + size fields)
HEAP_METADATA_SIZE = 16
# tcache sweet spot: chunks in bins 0x20-0x410 (idx 0-63)
TCACHE_MAX_SIZE = 0x410
TCACHE_MIN_SIZE = 0x20
# mmap threshold — chunks above this bypass heap entirely
MMAP_THRESHOLD = 128 * 1024

# Known kernel subsystems for attack surface classification
_KERNEL_NET_FUNCS = re.compile(
    r'(?:tcp_|udp_|ip_|ip6_|netfilter_|nf_|sk_|sock_|net_|sctp_|icmp_|arp_|'
    r'xfrm_|ipsec_|nl_|genl_|ieee802|cfg80211|mac80211|bluetooth|bt_|l2cap_|'
    r'rfcomm_|nfc_|can_|packet_|af_)', re.I)
_KERNEL_FS_FUNCS = re.compile(
    r'(?:ntfs3?_|ext[234]_|btrfs_|xfs_|fat_|vfat_|fuse_|nfs_|cifs_|smb_|'
    r'f2fs_|jfs_|reiserfs_|udf_|iso9660_|squashfs_|overlayfs_|ecryptfs_|'
    r'exfat_|hfs_|nilfs_|erofs_|tmpfs_|sysfs_|proc_|devpts_)', re.I)
_KERNEL_DRIVER_FUNCS = re.compile(
    r'(?:usb_|hid_|input_|drm_|gpu_|i2c_|spi_|pci_|acpi_|dma_|irq_|'
    r'v4l2_|media_|alsa_|snd_|video_)', re.I)


def analyze(report: AsanReport) -> dict:
    """
    Analyze exploitability with context-aware scoring.
    Returns dict with severity, score, factors, one_liner.
    """
    factors = []
    score = 0
    bt = report.bug_type
    at = report.access_type
    size = report.access_size or 0
    heap = report.heap_info
    stack = report.stack_info

    # ────────────────────────────────────────────
    # Null dereference — almost never exploitable
    # ────────────────────────────────────────────
    if report.is_null_deref:
        if report.is_kasan:
            # Kernel null deref is more interesting
            if at == "WRITE":
                score = 45
                factors.append("Kernel NULL write — exploitable if SMAP/SMEP disabled or via userfaultfd")
            else:
                score = 15
                factors.append("Kernel NULL read — info leak or DoS, not directly exploitable with modern mitigations")
        elif at == "WRITE":
            score = 25
            factors.append("NULL write — only exploitable on legacy systems (no guard pages) or embedded targets")
        else:
            score = 5
            factors.append("NULL read — denial of service only on modern systems")
        return _finalize(report, score, factors)

    # ────────────────────────────────────────────
    # SEGV on non-null (non-GDB, non-KASAN)
    # ────────────────────────────────────────────
    if report.is_segv and not report.is_null_deref and not report.is_gdb and not report.is_kasan:
        if at == "WRITE":
            score = 40
            factors.append("SEGV on write to unmapped address — may indicate controlled write to arbitrary address")
        else:
            addr = report.access_address or 0
            if addr > 0x7f0000000000:
                score = 20
                factors.append("SEGV reading near stack region — possible stack info leak or use-after-return")
            else:
                score = 15
                factors.append("SEGV on read from unmapped address — likely DoS")
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # KERNEL (KASAN) — different threat model
    # ════════════════════════════════════════════
    if report.is_kasan:
        score, factors = _score_kasan(report, bt, at, size, heap)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # GDB crashes — register-level analysis
    # ════════════════════════════════════════════
    if report.is_gdb:
        score, factors = _score_gdb(report, bt, at, size, stack)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # HEAP USE-AFTER-FREE
    # ════════════════════════════════════════════
    if bt == "heap-use-after-free":
        score, factors = _score_uaf(report, at, size, heap)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # DOUBLE FREE
    # ════════════════════════════════════════════
    if bt == "double-free":
        score, factors = _score_double_free(report, heap)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # HEAP BUFFER OVERFLOW / UNDERFLOW
    # ════════════════════════════════════════════
    if bt in ("heap-buffer-overflow", "heap-buffer-underflow"):
        score, factors = _score_heap_oob(report, bt, at, size, heap)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # STACK BUFFER OVERFLOW / UNDERFLOW
    # ════════════════════════════════════════════
    if bt in ("stack-buffer-overflow", "stack-buffer-underflow"):
        score, factors = _score_stack_oob(report, bt, at, size, stack)
        return _finalize(report, score, factors)

    # ════════════════════════════════════════════
    # OTHER BUG TYPES
    # ════════════════════════════════════════════

    if bt == "stack-use-after-return":
        score = 40 if at == "WRITE" else 25
        factors.append("Stack use-after-return: dangling pointer to recycled stack frame")
        if at == "WRITE":
            factors.append("Write to returned stack frame — can corrupt new frame's locals/return address")

    elif bt == "global-buffer-overflow":
        if at == "WRITE":
            score = 45
            factors.append("Global buffer overflow WRITE — may corrupt adjacent global variables, function pointers, or GOT (if no Full RELRO)")
        else:
            score = 20
            factors.append("Global buffer overflow READ — info leak from .bss/.data section")

    elif bt == "container-overflow":
        if at == "WRITE":
            score = 30
            factors.append("Container overflow WRITE — within container reserved memory, may corrupt container metadata")
        else:
            score = 15
            factors.append("Container overflow READ — minor info leak within reserved memory")

    elif bt == "use-of-uninitialized-value":
        score = 15
        factors.append("Use of uninitialized memory — may leak stack/heap contents or cause logic bugs")
        if size >= 8:
            score = 20
            factors.append(f"Reading {size}B of uninitialized data — could leak pointers (ASLR bypass)")

    elif bt in ("integer-overflow", "invalid-shift"):
        score = 20
        factors.append(f"{bt}: undefined behavior that often gates a subsequent memory corruption")
        factors.append("Check if this overflow controls a size passed to malloc/memcpy — if so, it's a heap overflow in disguise")

    elif bt == "division-by-zero":
        score = 5
        factors.append("Division by zero — DoS only, no memory corruption")

    else:
        # Unknown/other
        if at == "WRITE":
            score = 35
            factors.append(f"Unknown bug type ({bt}) with WRITE primitive — needs manual analysis")
        else:
            score = 15
            factors.append(f"Unknown bug type ({bt}) — needs manual analysis")

    return _finalize(report, score, factors)


# ──────────────────────────────────────────────────
# Heap OOB scoring
# ──────────────────────────────────────────────────

def _score_heap_oob(report, bt, at, size, heap):
    factors = []
    score = 0

    if not heap:
        # No heap metadata — generic scoring
        if at == "WRITE":
            score = 50
            factors.append("Heap OOB write detected but no region metadata available")
        else:
            score = 20
            factors.append("Heap OOB read — potential info leak")
        return score, factors

    offset = heap.offset or 0
    region_size = heap.region_size or 0
    direction = heap.direction or "right"
    overflow_bytes = offset + size  # total bytes past boundary

    # ── Heap layout awareness ──
    # Determine if chunk is in tcache range (sweet spot for exploitation)
    # Actual malloc chunk size = region_size + metadata (16B)
    chunk_size = region_size + HEAP_METADATA_SIZE
    in_tcache = TCACHE_MIN_SIZE <= chunk_size <= TCACHE_MAX_SIZE
    is_mmap = chunk_size > MMAP_THRESHOLD
    tcache_sweet_spot = 0x20 <= chunk_size <= 0x80

    if at == "WRITE":
        # ── WRITE scoring — the money question: can we corrupt metadata? ──

        if overflow_bytes >= HEAP_METADATA_SIZE:
            # Can corrupt the entire next chunk header (size + prev_size)
            # This gives: arbitrary write via tcache poisoning, unlink, etc.
            score = 80
            factors.append(f"Overflow of {overflow_bytes}B past {region_size}B region — "
                          f"corrupts next chunk header (prev_size + size fields)")
            factors.append("Next chunk metadata corruption → tcache poisoning / fastbin dup → arbitrary write")

            if overflow_bytes > 64:
                score = 88
                factors.append(f"Wide corruption ({overflow_bytes}B) — can overwrite multiple adjacent chunks/objects")

            if size >= 4096:
                score = 92
                factors.append(f"Massive write ({size}B, likely memcpy/memmove overflow) — "
                              "wide heap corruption, high control over corrupted data")
        elif overflow_bytes >= 8:
            # Can corrupt at least the size field of next chunk
            score = 70
            factors.append(f"Overflow of {overflow_bytes}B — can corrupt next chunk's size field")
            factors.append("Chunk size corruption → overlapping chunks → type confusion")
        elif offset == 1 and size == 1:
            # Classic off-by-one null byte
            score = 60
            factors.append("Off-by-one null byte overflow — classic chunk shrinking attack")
            factors.append("Null byte overwrites next chunk's size LSB → overlapping chunks via consolidation")
        elif overflow_bytes <= 2:
            # Very small overflow
            score = 55
            factors.append(f"Small overflow ({overflow_bytes}B) — limited but may corrupt prev_in_use bit")
        else:
            # 3-7 bytes past boundary
            score = 65
            factors.append(f"Overflow of {overflow_bytes}B past boundary — partial metadata corruption")

        # Exact pointer-sized write at boundary → likely overwrites a pointer in adjacent object
        if size == 8 and offset <= HEAP_METADATA_SIZE:
            score = max(score, 75)
            factors.append("8-byte write at chunk boundary — likely overwrites pointer in adjacent object (function ptr, vtable, fd)")

        # ── Chunk size modifiers ──
        if in_tcache:
            score = min(score + 5, 95)
            factors.append(f"Chunk in tcache range ({chunk_size:#x}) — fewer integrity checks than fastbin/smallbin")
            if tcache_sweet_spot:
                score = min(score + 3, 95)
                factors.append(f"Chunk in tcache sweet spot ({chunk_size:#x}) — trivial tcache poisoning")
        elif is_mmap:
            score = max(score - 15, 30)
            factors.append(f"Chunk is mmap'd ({chunk_size:#x} > 128KB) — no adjacent heap chunks, exploitation is harder")

        # Underflow bonus — corrupts metadata BEFORE the chunk
        if bt == "heap-buffer-underflow":
            score = min(score + 8, 95)
            factors.append("Underflow direction → corrupts preceding chunk's metadata (size/fd/bk)")

    else:
        # ── READ scoring ──
        if offset > 256:
            score = 35
            factors.append(f"Large OOB read ({offset}B past boundary) — significant info leak across multiple chunks")
            factors.append("Can leak heap metadata, fd/bk pointers (ASLR bypass), or adjacent object data")
        elif offset > 64:
            score = 30
            factors.append(f"OOB read {offset}B past boundary — may leak adjacent chunk header/pointers")
        elif size >= 8:
            score = 25
            factors.append(f"OOB read of {size}B — can leak pointer-sized values for ASLR bypass")
        else:
            score = 18
            factors.append(f"Small OOB read ({size}B, {offset}B past boundary) — minor info leak")

        if in_tcache:
            factors.append(f"Chunk in tcache range — fd pointer leak = heap address disclosure")

    # Alloc/free trace availability
    if heap.alloc_trace:
        alloc_func = _first_user_func(heap.alloc_trace)
        if alloc_func:
            factors.append(f"Allocation in {alloc_func}() — review size calculation")

    return score, factors


# ──────────────────────────────────────────────────
# UAF scoring
# ──────────────────────────────────────────────────

def _score_uaf(report, at, size, heap):
    factors = []
    score = 0
    region_size = heap.region_size if heap else 0
    chunk_size = region_size + HEAP_METADATA_SIZE

    if at == "WRITE":
        # UAF WRITE = you can write into a freed chunk that may have been reallocated
        # This means: type confusion, vtable overwrite, freelist poisoning
        score = 85
        factors.append("Use-after-free WRITE — can corrupt reallocated object's contents")
        factors.append("If freed object is reallocated as different type → type confusion → code execution")

        if size >= 8:
            score = 88
            factors.append(f"Write of {size}B — enough to overwrite function pointer or vtable entry")

        if heap and heap.free_trace:
            factors.append("Free trace available — can analyze reuse window for heap feng shui timing")
    else:
        # UAF READ = info leak from freed chunk (fd/bk pointers, or new object's data)
        score = 45
        factors.append("Use-after-free READ — leaks freed chunk data (heap pointers, or reallocated object)")

        if size >= 8:
            score = 50
            factors.append(f"Read of {size}B from freed chunk — can leak fd pointer = heap address (ASLR bypass)")

        if heap and heap.free_trace:
            score += 3
            factors.append("Free trace available — reuse window analyzable for info leak timing")

    # Chunk size affects exploit technique
    if region_size > 0:
        in_tcache = TCACHE_MIN_SIZE <= chunk_size <= TCACHE_MAX_SIZE
        if in_tcache:
            score = min(score + 4, 95)
            factors.append(f"Freed chunk in tcache range ({chunk_size:#x}) — easy to reclaim via same-size allocation")
            if 0x20 <= chunk_size <= 0x80:
                factors.append("Small tcache chunk — high allocation frequency, easy heap spray")
        elif chunk_size > MMAP_THRESHOLD:
            score = max(score - 10, 35)
            factors.append(f"Large freed chunk ({chunk_size:#x}) — harder to reclaim precisely")

    return score, factors


# ──────────────────────────────────────────────────
# Double-free scoring
# ──────────────────────────────────────────────────

def _score_double_free(report, heap):
    factors = []
    region_size = heap.region_size if heap else 0
    chunk_size = region_size + HEAP_METADATA_SIZE

    # Double-free on modern glibc (2.32+) has tcache key detection
    # But if it's triggered, the program is already crashing at the second free()
    # The real danger is if the attacker can work around the check

    score = 65
    factors.append("Double-free detected — freelist corruption leads to arbitrary write primitive")
    factors.append("Two malloc() calls return same chunk → overlapping objects → type confusion")

    if region_size > 0:
        in_tcache = TCACHE_MIN_SIZE <= chunk_size <= TCACHE_MAX_SIZE
        if in_tcache:
            score = 70
            factors.append(f"Chunk in tcache range ({chunk_size:#x}) — classic tcache dup attack")
            factors.append("Note: glibc 2.32+ has tcache key mitigation — may need to corrupt key first")
            if 0x20 <= chunk_size <= 0x80:
                score = 75
                factors.append("Small tcache chunk — ideal for tcache dup, many allocation opportunities")
        else:
            factors.append(f"Chunk outside tcache range ({chunk_size:#x}) — fastbin dup or unsorted bin attack needed")

    return score, factors


# ──────────────────────────────────────────────────
# Stack OOB scoring
# ──────────────────────────────────────────────────

def _score_stack_oob(report, bt, at, size, stack):
    factors = []
    score = 0

    if at == "WRITE":
        var_name = stack.variable_name if stack else "buffer"
        var_size = stack.variable_size if stack else 0
        offset = stack.offset if stack else 0
        direction = stack.direction if stack else "right"

        # Base: stack overflow write is always interesting
        score = 60

        if direction == "right":
            factors.append("Overflow direction toward saved RBP / return address")

            # How far past the buffer end?
            if var_size > 0 and offset > 0:
                total_overflow = offset
                # Stack layout: [buffer][padding][canary(8)][saved_rbp(8)][ret_addr(8)]
                # Distance from buffer end to ret addr ≈ 24 bytes (with canary) or 16 (without)
                if total_overflow > 24:
                    score = 78
                    factors.append(f"Overflow of {total_overflow}B past {var_size}B buffer — "
                                  "well past return address (canary + RBP + RIP smashed)")
                elif total_overflow > 16:
                    score = 72
                    factors.append(f"Overflow of {total_overflow}B — reaches saved RBP and possibly return address")
                elif total_overflow > 8:
                    score = 65
                    factors.append(f"Overflow of {total_overflow}B — reaches canary or saved RBP region")
                else:
                    factors.append(f"Small overflow ({total_overflow}B) — may not reach return address")
            elif size > 64:
                score = 75
                factors.append(f"Large stack write ({size}B) — high likelihood of smashing return address")
            elif size > 16:
                score = 68
                factors.append(f"Stack write of {size}B — likely reaches saved registers")

        elif direction == "left":
            score = 50
            factors.append("Underflow toward lower stack addresses — corrupts other local variables")
            if size > 32:
                score = 55
                factors.append("Large underflow may corrupt variables used in security checks")

        # If we have definitive proof of RIP control from the crash itself
        if report.crash_trace:
            # Check if crash address looks like a pattern value
            crash_addr = report.crash_trace[0].address if report.crash_trace else 0
            pattern_vals_32 = {0x41414141, 0x42424242, 0x43434343, 0x44444444}
            pattern_vals_64 = {0x4141414141414141, 0x4242424242424242,
                               0x4343434343434343, 0x4444444444444444}
            if crash_addr in pattern_vals_64 or crash_addr in pattern_vals_32:
                score = 92
                factors.append(f"Crash at pattern address {hex(crash_addr)} — CONFIRMED RIP control!")

    else:
        # Stack OOB read
        score = 22
        factors.append("Stack buffer overflow READ — leaks stack contents")
        if size >= 8:
            score = 28
            factors.append("Can leak canary value, saved RBP, return address → defeats ASLR + canary")

    return score, factors


# ──────────────────────────────────────────────────
# GDB crash scoring — register-level precision
# ──────────────────────────────────────────────────

def _score_gdb(report, bt, at, size, stack):
    factors = []
    score = 0
    regs = report.registers

    # Pattern values we planted in the input
    pattern_vals_64 = {
        0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
        0x4444444444444444, 0x4545454545454545, 0x4646464646464646,
        0x4747474747474747, 0x4848484848484848,
    }
    pattern_vals_32 = {v & 0xFFFFFFFF for v in pattern_vals_64}

    def _is_controlled(val):
        return (val in pattern_vals_64 or
                (val & 0xFFFFFFFF) in pattern_vals_32 or
                # De Bruijn / cyclic pattern heuristic: all bytes are printable ASCII
                (val > 0x20202020 and all(0x20 <= ((val >> (i*8)) & 0xFF) <= 0x7E for i in range(8 if val > 0xFFFFFFFF else 4))))

    # ── Classify every register ──
    controlled_regs = []
    gp_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    for reg in gp_regs:
        if reg in regs and _is_controlled(regs[reg]):
            controlled_regs.append(reg)

    rip_controlled = "rip" in regs and _is_controlled(regs["rip"])
    rbp_controlled = "rbp" in regs and _is_controlled(regs["rbp"])
    rsp_valid = "rsp" in regs and regs["rsp"] > 0x7f0000000000  # still points to stack

    # Callee-saved registers (survive across calls → useful for ROP gadgets)
    callee_saved = [r for r in controlled_regs if r in ("rbx", "r12", "r13", "r14", "r15")]

    # Argument registers (control function call arguments)
    arg_regs = [r for r in controlled_regs if r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")]

    # Count controlled stack frames (pattern values in return addresses)
    controlled_frames = 0
    for f in report.crash_trace:
        if _is_controlled(f.address):
            controlled_frames += 1

    num_controlled = len(controlled_regs)

    # ── Detect canary presence (heuristic) ──
    # If crash happened in __stack_chk_fail, canary was NOT bypassed
    canary_triggered = any(
        f.function and "__stack_chk_fail" in f.function
        for f in report.crash_trace
    )

    # ── Scoring ──
    if rip_controlled:
        score = 92
        factors.append(f"RIP CONTROLLED ({hex(regs['rip'])}) — direct code execution primitive")
        if rsp_valid:
            score = 95
            factors.append("RSP still valid — stack pivot not needed, direct ROP chain possible")
        if not rsp_valid:
            factors.append("RSP corrupted — need gadget that doesn't use stack, or stack pivot via controlled RBP")
    elif canary_triggered:
        score = 40
        factors.append("Crash in __stack_chk_fail — stack canary detected the overflow")
        factors.append("Canary NOT bypassed — need info leak (format string, OOB read) to leak canary first")
        if num_controlled > 0:
            score = 50
            factors.append(f"But {num_controlled} registers controlled — overflow is real, just need canary bypass")
    elif rbp_controlled:
        score = 78
        factors.append(f"RBP CONTROLLED ({hex(regs['rbp'])}) — stack pivot possible on function return")
        factors.append("leave; ret sequence will set RSP = controlled RBP → ROP chain at attacker-chosen address")
    elif controlled_frames > 0:
        # Stack frames have pattern values but RIP doesn't (maybe ASLR randomized it)
        score = 72
        factors.append(f"{controlled_frames} stack frame(s) contain pattern values — return addresses partially smashed")
    elif num_controlled >= 4:
        score = 65
        factors.append(f"{num_controlled} general-purpose registers controlled — significant control over execution")
    elif num_controlled >= 2:
        score = 55
        factors.append(f"{num_controlled} registers controlled — partial control")
    elif num_controlled >= 1:
        score = 45
        factors.append(f"1 register controlled ({controlled_regs[0]}) — limited primitive")
    else:
        score = 30
        factors.append("No registers contain recognizable pattern values — may not be directly controllable")

    # ── Register detail factors ──
    if callee_saved and not rip_controlled:
        score = min(score + 5, 95)
        factors.append(f"Callee-saved registers controlled ({', '.join(callee_saved)}) — "
                      "survive across function calls, usable as ROP gadget operands")

    if arg_regs and not rip_controlled:
        score = min(score + 5, 95)
        factors.append(f"Argument registers controlled ({', '.join(arg_regs)}) — "
                      "control arguments to next function call")

    # ── Overflow offset estimation from frame count ──
    if controlled_frames > 0:
        estimated_offset = controlled_frames * 8  # each frame = 8 bytes
        factors.append(f"Estimated overflow past return address: ~{estimated_offset}B ({controlled_frames} frames × 8B)")

    return score, factors


# ──────────────────────────────────────────────────
# KASAN (kernel) scoring
# ──────────────────────────────────────────────────

def _score_kasan(report, bt, at, size, heap):
    factors = []
    score = 0

    # Identify kernel attack surface from function names in trace
    funcs = [f.function or "" for f in (report.crash_trace or [])]
    all_funcs_str = " ".join(funcs)

    is_net = bool(_KERNEL_NET_FUNCS.search(all_funcs_str))
    is_fs = bool(_KERNEL_FS_FUNCS.search(all_funcs_str))
    is_driver = bool(_KERNEL_DRIVER_FUNCS.search(all_funcs_str))
    is_syscall = any("sys_" in f or "SyS_" in f or "__x64_sys" in f for f in funcs)

    # ── Base scoring by bug type ──
    if bt in ("heap-buffer-overflow", "heap-buffer-underflow"):
        if at == "WRITE":
            score = 70
            factors.append("Kernel slab OOB write — can corrupt adjacent slab objects")
            if heap:
                offset = heap.offset or 0
                region_size = heap.region_size or 0
                if offset >= 8:
                    score = 78
                    factors.append(f"Overflow of {offset}B past {region_size}B slab object — "
                                  "can corrupt function pointers in adjacent object")
                if size >= 64:
                    score = 82
                    factors.append(f"Large kernel write ({size}B) — wide slab corruption, cross-cache attack viable")
            factors.append("Exploitation: cross-cache attack with msg_msg/pipe_buffer spray → arbitrary write → modprobe_path overwrite")
        else:
            score = 40
            factors.append("Kernel slab OOB read — info leak from adjacent slab objects")
            if heap and heap.offset and heap.offset > 64:
                score = 50
                factors.append(f"Large OOB read ({heap.offset}B) — can leak kernel pointers (KASLR bypass)")

    elif bt == "heap-use-after-free":
        if at == "WRITE":
            score = 85
            factors.append("Kernel UAF WRITE — can corrupt reallocated slab object")
            factors.append("Cross-cache exploitation: free victim, reclaim with pipe_buffer/msg_msg → arbitrary write")
        else:
            score = 55
            factors.append("Kernel UAF READ — leak freed slab object data (kernel pointers)")

    elif bt == "double-free":
        score = 72
        factors.append("Kernel double-free — SLUB freelist corruption → arbitrary slab allocation")

    elif bt in ("stack-buffer-overflow", "stack-buffer-underflow"):
        if at == "WRITE":
            score = 75
            factors.append("Kernel stack overflow — can corrupt kernel return address")
            factors.append("No ASLR for stack layout within a syscall — fixed offsets")
        else:
            score = 40
            factors.append("Kernel stack OOB read — leak kernel stack contents")

    else:
        if at == "WRITE":
            score = 55
            factors.append(f"Kernel {bt} with WRITE — needs manual analysis")
        else:
            score = 30
            factors.append(f"Kernel {bt} — needs manual analysis")

    # ── Attack surface modifiers ──
    if is_net:
        score = min(score + 12, 98)
        factors.append("⚡ REMOTE TRIGGER — network subsystem code path → remote code execution / LPE without physical access")
    elif is_fs:
        score = min(score + 5, 95)
        factors.append("Filesystem code path — trigger by mounting crafted image (USB/network share) → physical access LPE")
    elif is_driver:
        score = min(score + 3, 95)
        factors.append("Device driver code path — trigger via hardware/device interaction")
    elif is_syscall:
        score = min(score + 7, 95)
        factors.append("Reachable via syscall — local privilege escalation from unprivileged user")

    # Specific filesystem context
    for func in funcs:
        if "ntfs" in func.lower():
            factors.append("ntfs3 filesystem — triggered by mounting crafted NTFS image")
            break
        elif "ext4" in func.lower():
            factors.append("ext4 filesystem — triggered by crafted ext4 image or journal replay")
            break

    return score, factors


# ──────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────

_SKIP_FUNCS = {"__interceptor_memcpy", "__interceptor_memmove", "__interceptor_memset",
               "__interceptor_strcpy", "__asan_memcpy", "__asan_memmove",
               "malloc", "calloc", "realloc", "free",
               "__interceptor_malloc", "__interceptor_free",
               "__interceptor_calloc", "__interceptor_realloc",
               "operator new", "operator delete"}


def _first_user_func(trace):
    """Return first non-sanitizer/libc function from a trace."""
    for f in (trace or []):
        if f.function and f.function not in _SKIP_FUNCS:
            return f.function
    return ""


def _finalize(report: AsanReport, score: int, factors: list[str]) -> dict:
    score = max(0, min(100, score))

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 55:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    elif score >= 15:
        severity = "LOW"
    else:
        severity = "NOT EXPLOITABLE"

    one_liner = _make_one_liner(report, severity)

    return {
        "severity": severity,
        "score": score,
        "factors": factors,
        "one_liner": one_liner,
    }


def _make_one_liner(report: AsanReport, severity: str) -> str:
    bt = report.bug_type.replace("-", " ").title()
    at = report.access_type or "access"
    parts = [bt]

    if report.access_size:
        parts.append(f"({at} of {report.access_size} bytes)")

    if report.heap_info and report.heap_info.offset:
        parts.append(f"{report.heap_info.offset}B {report.heap_info.direction} of {report.heap_info.region_size}B region")

    func = ""
    if report.crash_trace:
        func = report.crash_trace[0].function
        if func:
            parts.append(f"in {func}")

    parts.append(f"[{severity}]")
    return " ".join(parts)

