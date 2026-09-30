"""
Shared Volatility3 automation layer for the Memory Analysis Father Agent and
its four sub-modules. Runs Volatility3 plugins against a staged memory image
and returns their output as plain Python data -- every sub-module builds on
top of run_plugin() instead of re-implementing subprocess plumbing.

The backend is pluggable (VolatilityBackend) so a Model Context Protocol
transport can be dropped in later without touching a single sub-module: the
default (SubprocessVolatilityBackend) shells out to the `vol` CLI with
`-r json`, which is Volatility3's own supported automation surface -- the
same subprocess-based automation pattern collectors/collector.py already
uses for every other forensic tool in this project.
"""
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

MEMORY_IMAGE_EXTENSIONS = (".raw", ".dmp", ".vmem", ".mem", ".lime")


def locate_memory_image(staging_root: Path) -> Optional[Path]:
    """Finds the memory dump staged into MemoryDumps/raw/ (see
    collectors/collector.py's scope=MEMORY handling, and the field kit's
    README -- the analyst drops the image there manually since it isn't
    something the collector can acquire itself). If more than one file
    matches, returns the largest -- a stray small file alongside it is more
    likely a notes/checksum sidecar than a second full image."""
    raw_dir = Path(staging_root) / "MemoryDumps" / "raw"
    if not raw_dir.is_dir():
        return None
    candidates = [
        p for p in raw_dir.iterdir()
        if p.is_file() and p.suffix.lower() in MEMORY_IMAGE_EXTENSIONS
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def sha256_of_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> Optional[str]:
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


def md5_of_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> Optional[str]:
    try:
        hasher = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


_MALFIND_DUMP_RE = re.compile(r"pid\.(\d+)\..*?(0x)?([0-9a-fA-F]{4,16})\.dmp$")


def find_malfind_dump(output_dir: Path, pid: int, virtual_address: str) -> Optional[Path]:
    """windows.malfind.Malfind --dump writes files named like
    pid.<pid>.vad.<hex-start>-<hex-end>.dmp into the -o output directory.
    Matches by PID first (cheap, always present in the filename) then by the
    VA appearing anywhere in the name, since exact separator formatting has
    drifted across Volatility3 releases."""
    if not output_dir.is_dir():
        return None
    va_clean = virtual_address.lower().replace("0x", "")
    for candidate in output_dir.glob(f"pid.{pid}.*.dmp"):
        if va_clean in candidate.name.lower():
            return candidate
    # Fall back to PID-only match if the VA formatting didn't line up.
    pid_matches = list(output_dir.glob(f"pid.{pid}.*.dmp"))
    return pid_matches[0] if pid_matches else None


def sniff_pe_header(path: Path, sniff_bytes: int = 64) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(sniff_bytes).startswith(b"MZ")
    except Exception:
        return False


class VolatilityError(RuntimeError):
    """A plugin invocation failed outright (binary missing, bad image, plugin
    crashed). Callers of the module-level run_plugin() never see this -- it's
    caught and degraded to a logged warning + empty result, mirroring how
    collectors/collector.py treats a missing/failing external tool: a
    warning, never a fatal crash of the whole investigation."""


class VolatilityBackend:
    """Interface every backend implements: run one plugin, get back parsed rows."""

    def run_plugin(self, image_path: Path, plugin: str, args: Optional[List[str]] = None,
                    output_dir: Optional[Path] = None, timeout: int = 300) -> List[Dict[str, Any]]:
        raise NotImplementedError


class SubprocessVolatilityBackend(VolatilityBackend):
    """Shells out to the `vol` CLI (pip install volatility3) with the JSON
    renderer. This is today's implementation of the "API automation" half of
    the brief; an MCPVolatilityBackend can be added later purely as another
    VolatilityBackend and swapped in via set_backend() -- no sub-module code
    changes, since they only ever call the module-level run_plugin()."""

    def __init__(self, vol_binary: Optional[str] = None):
        self.vol_binary = vol_binary or self._detect_vol_binary()

    @staticmethod
    def _detect_vol_binary() -> str:
        for candidate in ("vol", "vol.py", "volatility3"):
            if shutil.which(candidate):
                return candidate
        # Sentinel: run as `python -m volatility3.cli` instead of a console
        # script, for environments where only the package (not its entry
        # point) made it onto PATH.
        return "__module__"

    def run_plugin(self, image_path: Path, plugin: str, args: Optional[List[str]] = None,
                    output_dir: Optional[Path] = None, timeout: int = 300) -> List[Dict[str, Any]]:
        cmd = ["python", "-m", "volatility3.cli"] if self.vol_binary == "__module__" else [self.vol_binary]
        # --offline: Volatility3 otherwise tries to fetch missing ISF symbol
        # tables from downloads.volatilityfoundation.org on an unrecognized
        # OS build -- this platform is designed to run fully offline, so
        # that reach-out should never happen (it would just hang/fail slowly
        # on an air-gapped analyst machine). Falls back to whatever symbols
        # are already cached locally, same as every other external tool in
        # this codebase degrading gracefully instead of calling out.
        cmd += ["-q", "-r", "json", "--offline", "-f", str(image_path)]
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            cmd += ["-o", str(output_dir)]
        cmd.append(plugin)
        if args:
            cmd += args

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as e:
            raise VolatilityError(f"Volatility3 binary not found ({self.vol_binary}): {e}") from e
        except subprocess.TimeoutExpired as e:
            raise VolatilityError(f"{plugin} timed out after {timeout}s") from e

        if result.returncode != 0:
            raise VolatilityError(f"{plugin} exited {result.returncode}: {result.stderr[-2000:]}")

        stdout = result.stdout.strip()
        if not stdout:
            return []
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            raise VolatilityError(f"{plugin} produced non-JSON output: {e}") from e


_backend: VolatilityBackend = SubprocessVolatilityBackend()


def set_backend(backend: VolatilityBackend) -> None:
    """Swap the module-level backend -- e.g. for an MCP transport in
    production, or a canned-rows test double in unit tests."""
    global _backend
    _backend = backend


def run_plugin(image_path: Path, plugin: str, args: Optional[List[str]] = None,
                output_dir: Optional[Path] = None, timeout: int = 300) -> List[Dict[str, Any]]:
    """Every sub-module's one entry point into Volatility3. Never raises for
    an ordinary tool failure (missing binary, bad image, plugin crash,
    timeout) -- logs a warning through the bridge if one is running, and
    returns [] so the calling agent can still submit a partial/degraded
    report instead of taking the whole investigation down."""
    try:
        return _backend.run_plugin(image_path, plugin, args=args, output_dir=output_dir, timeout=timeout)
    except VolatilityError as e:
        message = f"{plugin} failed against {image_path.name}: {e}"
        try:
            from bridge.hitl_bridge import bridge
            bridge.log_event("Volatility", message, level="WARN")
        except Exception:
            print(f"[Volatility][WARN] {message}")
        return []
