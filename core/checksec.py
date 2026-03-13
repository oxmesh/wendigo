"""Binary security checks — checksec equivalent for ELF binaries."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BinarySecurity:
    """Security features detected in a binary."""
    pie: bool = False
    nx: bool = False
    relro: str = "None"  # "None", "Partial", "Full"
    canary: bool = False
    fortify: bool = False
    binary_path: str = ""
    arch: str = ""
    bits: int = 64

    def to_dict(self):
        return {
            "pie": self.pie,
            "nx": self.nx,
            "relro": self.relro,
            "canary": self.canary,
            "fortify": self.fortify,
            "binary_path": self.binary_path,
            "arch": self.arch,
            "bits": self.bits,
        }

    def format_line(self):
        """Format as a single-line summary with emoji indicators."""
        def _yn(val, label):
            return f"{label} {'✅' if val else '❌'}"
        parts = [
            _yn(self.pie, "PIE"),
            _yn(self.nx, "NX"),
            f"RELRO: {self.relro}",
            _yn(self.canary, "Canary"),
            _yn(self.fortify, "FORTIFY"),
        ]
        return "  ".join(parts)

    def exploitability_adjustments(self, bug_type: str, access_type: str) -> list:
        """Return (score_delta, reason) tuples based on security features + bug type."""
        adjustments = []

        if bug_type in ("stack-buffer-overflow", "stack-buffer-underflow"):
            if not self.canary:
                adjustments.append((15, "No stack canary — direct return address overwrite possible"))
            else:
                adjustments.append((-10, "Stack canary present — need info leak to bypass"))

        if not self.pie:
            adjustments.append((10, "No PIE — fixed addresses, GOT/PLT overwrite trivial"))

        if self.relro == "None":
            adjustments.append((5, "No RELRO — GOT fully writable"))
        elif self.relro == "Partial":
            adjustments.append((3, "Partial RELRO — GOT still writable"))

        if not self.nx:
            adjustments.append((10, "NX disabled — shellcode injection possible"))

        if not self.fortify and access_type == "WRITE":
            adjustments.append((2, "No FORTIFY_SOURCE — unsafe libc functions not hardened"))

        return adjustments


def check_binary_security(binary: str) -> BinarySecurity:
    """Analyze an ELF binary for security features using readelf."""
    result = BinarySecurity(binary_path=str(binary))

    binary = str(Path(binary).resolve())
    if not os.path.isfile(binary):
        return result

    try:
        # Get ELF header info
        hdr = subprocess.run(
            ["readelf", "-h", binary],
            capture_output=True, text=True, timeout=5
        )
        if hdr.returncode == 0:
            output = hdr.stdout
            if "ELF64" in output:
                result.bits = 64
            elif "ELF32" in output:
                result.bits = 32

            m = re.search(r"Machine:\s+(.+)", output)
            if m:
                result.arch = m.group(1).strip()

            # PIE: Type is DYN (Position-Independent Executable)
            if re.search(r"Type:\s+DYN", output):
                result.pie = True

        # Check program headers for NX and RELRO
        phdr = subprocess.run(
            ["readelf", "-l", binary],
            capture_output=True, text=True, timeout=5
        )
        if phdr.returncode == 0:
            output = phdr.stdout
            # NX: GNU_STACK without E (execute) flag
            stack_match = re.search(r"GNU_STACK\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+(\S+)", output)
            if stack_match:
                flags = stack_match.group(1)
                result.nx = "E" not in flags
            else:
                # If no GNU_STACK segment, NX is typically enabled
                result.nx = True

            # RELRO: GNU_RELRO segment present
            if "GNU_RELRO" in output:
                result.relro = "Partial"

        # Check dynamic section for BIND_NOW (Full RELRO)
        dyn = subprocess.run(
            ["readelf", "-d", binary],
            capture_output=True, text=True, timeout=5
        )
        if dyn.returncode == 0:
            output = dyn.stdout
            if "BIND_NOW" in output:
                result.relro = "Full"

        # Check for stack canary and FORTIFY symbols
        syms = subprocess.run(
            ["readelf", "-s", binary],
            capture_output=True, text=True, timeout=5
        )
        if syms.returncode == 0:
            output = syms.stdout
            if "__stack_chk_fail" in output:
                result.canary = True
            if "_chk@" in output or "__fortify" in output.lower():
                result.fortify = True

        # Also check dynamic symbols
        dynsyms = subprocess.run(
            ["readelf", "--dyn-syms", binary],
            capture_output=True, text=True, timeout=5
        )
        if dynsyms.returncode == 0:
            output = dynsyms.stdout
            if "__stack_chk_fail" in output:
                result.canary = True
            if "_chk@" in output or "__fortify" in output.lower():
                result.fortify = True

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return result

