"""CWE classification and exploitation hints for crash types."""

# Bug type → CWE mapping
CWE_MAP = {
    "heap-buffer-overflow": {"id": "CWE-122", "name": "Heap-based Buffer Overflow",
                             "url": "https://cwe.mitre.org/data/definitions/122.html"},
    "heap-buffer-underflow": {"id": "CWE-122", "name": "Heap-based Buffer Overflow",
                              "url": "https://cwe.mitre.org/data/definitions/122.html"},
    "stack-buffer-overflow": {"id": "CWE-121", "name": "Stack-based Buffer Overflow",
                              "url": "https://cwe.mitre.org/data/definitions/121.html"},
    "stack-buffer-underflow": {"id": "CWE-121", "name": "Stack-based Buffer Overflow",
                               "url": "https://cwe.mitre.org/data/definitions/121.html"},
    "heap-use-after-free": {"id": "CWE-416", "name": "Use After Free",
                            "url": "https://cwe.mitre.org/data/definitions/416.html"},
    "double-free": {"id": "CWE-415", "name": "Double Free",
                    "url": "https://cwe.mitre.org/data/definitions/415.html"},
    "null-deref": {"id": "CWE-476", "name": "NULL Pointer Dereference",
                   "url": "https://cwe.mitre.org/data/definitions/476.html"},
    "null-dereference": {"id": "CWE-476", "name": "NULL Pointer Dereference",
                         "url": "https://cwe.mitre.org/data/definitions/476.html"},
    "integer-overflow": {"id": "CWE-190", "name": "Integer Overflow or Wraparound",
                         "url": "https://cwe.mitre.org/data/definitions/190.html"},
    "use-of-uninitialized-value": {"id": "CWE-457", "name": "Use of Uninitialized Variable",
                                   "url": "https://cwe.mitre.org/data/definitions/457.html"},
    "global-buffer-overflow": {"id": "CWE-120", "name": "Buffer Copy without Checking Size of Input",
                               "url": "https://cwe.mitre.org/data/definitions/120.html"},
    "container-overflow": {"id": "CWE-787", "name": "Out-of-bounds Write",
                           "url": "https://cwe.mitre.org/data/definitions/787.html"},
    "stack-use-after-return": {"id": "CWE-562", "name": "Return of Stack Variable Address",
                               "url": "https://cwe.mitre.org/data/definitions/562.html"},
    "invalid-free": {"id": "CWE-761", "name": "Free of Pointer not at Start of Buffer",
                     "url": "https://cwe.mitre.org/data/definitions/761.html"},
}


def get_cwe(bug_type: str) -> dict:
    """Get CWE classification for a bug type. Returns dict with id, name, url or empty dict."""
    return CWE_MAP.get(bug_type, {})


def get_exploitation_hints(bug_type: str, access_type: str, security=None) -> list:
    """Generate exploitation strategy hints based on bug type + binary security.

    Args:
        bug_type: The vulnerability type string
        access_type: "READ" or "WRITE"
        security: BinarySecurity object (optional)

    Returns:
        List of hint strings
    """
    hints = []
    has_pie = security.pie if security else True
    has_canary = security.canary if security else True
    relro = security.relro if security else "Full"
    has_nx = security.nx if security else True

    if bug_type in ("heap-buffer-overflow", "heap-buffer-underflow"):
        if access_type == "WRITE":
            if not has_pie:
                hints.append("Try overwriting GOT entry or function pointer in adjacent chunk")
            hints.append("Corrupt adjacent heap chunk metadata → unlink attack or tcache poisoning")
            if not has_pie and relro != "Full":
                hints.append("GOT overwrite feasible (no PIE + writable GOT)")
            hints.append("If adjacent chunk contains function pointer or vtable, overwrite for code execution")
        else:
            hints.append("OOB read → info leak: heap addresses, canary values, or vtable pointers")
            if has_pie:
                hints.append("Use leaked heap/code address to defeat ASLR/PIE")

    elif bug_type in ("heap-use-after-free",):
        if not has_pie:
            hints.append("Try tcache poisoning / fastbin dup to get arbitrary write → overwrite GOT")
        else:
            hints.append("Heap spray same-size allocation to control freed chunk contents")
        hints.append("If freed object had virtual methods, replace vtable pointer for code execution")
        hints.append("Use heap feng shui to place target object in freed slot")
        if access_type == "WRITE":
            hints.append("Write to freed chunk → corrupt freelist → arbitrary write primitive")

    elif bug_type in ("double-free",):
        hints.append("tcache dup → arbitrary write primitive")
        hints.append("Allocate twice from same slot → overlapping objects → type confusion")
        if not has_pie:
            hints.append("Write __free_hook or GOT entry for code execution")
        if not has_nx:
            hints.append("NX disabled — can write and execute shellcode directly")

    elif bug_type in ("stack-buffer-overflow", "stack-buffer-underflow"):
        if access_type == "WRITE":
            if not has_canary:
                hints.append("Direct return address overwrite → ROP chain (no canary!)")
                if not has_nx:
                    hints.append("NX disabled + no canary → direct shellcode on stack")
                else:
                    hints.append("Build ROP chain using gadgets from binary" +
                                (" (fixed addresses, no PIE)" if not has_pie else ""))
            else:
                hints.append("Need info leak to bypass stack canary, or try canary brute-force (forking server)")
                hints.append("Check if there's a format string or OOB read to leak canary first")
        else:
            hints.append("Stack OOB read → leak canary, saved RBP, return address for ASLR bypass")

    elif bug_type in ("null-deref", "null-dereference"):
        if access_type == "WRITE":
            hints.append("Null write on kernel (no SMAP/SMEP) or embedded systems may be exploitable")
            hints.append("Check if mmap(NULL, ...) is possible to map page 0")
        else:
            hints.append("Typically DoS only — not exploitable on modern systems with guard pages")

    elif bug_type == "integer-overflow":
        hints.append("Integer overflow in size calculation → undersized allocation → heap overflow")
        hints.append("Check if the overflow controls a length passed to memcpy/malloc")

    return hints

