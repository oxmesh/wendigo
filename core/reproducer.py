"""Run a binary with ASAN and capture sanitizer output."""

import os
import subprocess
from pathlib import Path


def _build_hint(binary: str) -> str:
    """Generate a context-aware build hint based on what's in the binary's directory."""
    binary_dir = Path(binary).resolve().parent
    name = Path(binary).stem

    # Walk up to find project root (max 3 levels)
    for d in [binary_dir, binary_dir.parent, binary_dir.parent.parent]:
        if (d / "CMakeLists.txt").exists():
            return (
                f"  CMake project detected. Try:\n\n"
                f"    mkdir build_asan && cd build_asan\n"
                f"    cmake -DCMAKE_C_COMPILER=clang \\\n"
                f"          -DCMAKE_CXX_COMPILER=clang++ \\\n"
                f"          -DCMAKE_C_FLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"          -DCMAKE_CXX_FLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"          -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address\" ..\n"
                f"    make\n"
            )
        if (d / "configure").exists() or (d / "configure.ac").exists():
            return (
                f"  Autotools project detected. Try:\n\n"
                f"    CC=clang CXX=clang++ \\\n"
                f"    CFLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"    CXXFLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"    LDFLAGS=\"-fsanitize=address\" \\\n"
                f"    ./configure && make\n"
            )
        if (d / "Makefile").exists() or (d / "makefile").exists() or (d / "GNUmakefile").exists():
            return (
                f"  Makefile project detected. Try:\n\n"
                f"    make CC=clang CXX=clang++ \\\n"
                f"         CFLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"         CXXFLAGS=\"-fsanitize=address -g -O1\" \\\n"
                f"         LDFLAGS=\"-fsanitize=address\"\n"
            )
        if (d / "meson.build").exists():
            return (
                f"  Meson project detected. Try:\n\n"
                f"    CC=clang CXX=clang++ meson setup build_asan \\\n"
                f"      -Db_sanitize=address -Db_lundef=false\n"
                f"    ninja -C build_asan\n"
            )
        if (d / "Cargo.toml").exists():
            return (
                f"  Rust project detected. Try:\n\n"
                f"    RUSTFLAGS=\"-Zsanitizer=address\" \\\n"
                f"    cargo +nightly build --target x86_64-unknown-linux-gnu\n"
            )

    # Fallback — generic
    return (
        f"  clang -fsanitize=address -g -O1 -o {name}_asan <source files>\n\n"
        f"  Or if you already have ASAN logs, use:  wendigo --log crash_log.txt\n"
    )


def _is_asan_binary(binary: str) -> bool:
    """Check if a binary is built with AddressSanitizer."""
    try:
        # Check for __asan symbols in the binary
        result = subprocess.run(
            ["nm", "-D", binary], capture_output=True, text=True, timeout=5
        )
        if "__asan" in result.stdout:
            return True
        # nm -D might not work on static binaries, try strings
        result = subprocess.run(
            ["grep", "-c", "__asan", binary], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and int(result.stdout.strip()) > 0:
            return True
        return False
    except Exception:
        # If we can't check, don't block — let it run
        return True


ASAN_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:symbolize=1:print_legend=1:abort_on_error=1:halt_on_error=1",
    "ASAN_SYMBOLIZER_PATH": "",  # use default
}


def reproduce(
    binary: str,
    input_file: str | None = None,
    stdin_input: bool = False,
    args: list[str] | None = None,
    timeout: int = 30,
    env_extra: dict | None = None,
) -> tuple[int, str, str]:
    """
    Run binary with ASAN environment, feeding input_file as argument or stdin.
    Returns (returncode, stdout, stderr).
    """
    binary = str(Path(binary).resolve())
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"Binary not found: {binary}")
    if not os.access(binary, os.X_OK):
        raise PermissionError(f"Binary not executable: {binary}")

    # Check if binary is ASAN-instrumented
    if not _is_asan_binary(binary):
        raise RuntimeError(
            f"Binary is not built with AddressSanitizer: {Path(binary).name}\n\n"
            f"Wendigo needs ASAN output to classify crashes. Rebuild your target:\n\n"
            + _build_hint(binary)
        )

    cmd = [binary]
    if args:
        cmd.extend(args)

    stdin_data = None
    if input_file:
        input_path = Path(input_file).resolve()
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        if stdin_input:
            stdin_data = input_path.read_bytes()
        else:
            cmd.append(str(input_path))

    env = os.environ.copy()
    env.update(ASAN_ENV)
    if env_extra:
        env.update(env_extra)

    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        return result.returncode, result.stdout.decode("utf-8", errors="replace"), result.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT: Process exceeded {} seconds".format(timeout)
    except Exception as e:
        return -1, "", f"ERROR: {e}"

