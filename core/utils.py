import os
import glob
from pathlib import Path
from typing import Optional, Set


DEFAULT_EVENT_CONTEXT_FILENAME = "event_context.txt"
DEFAULT_IOC_LIST_FILENAME = "ioc_list.txt"
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
_MAX_EVENT_CONTEXT_CHARS = 4000


def locate_staging_directory(search_root: str = ".", explicit_path: Optional[str] = None) -> Path:
    if explicit_path:
        p = Path(explicit_path)
        if not p.exists():
            raise FileNotFoundError(f"Provided staging path does not exist: {p}")
        return p

    candidates = [Path(c) for c in glob.glob(os.path.join(search_root, "investigation_staging_*"))]
    candidates = [c for c in candidates if c.is_dir()]

    if not candidates:
        raise FileNotFoundError(
            f"No 'investigation_staging_*' folder found under '{search_root}'. "
            "Run collector_agent.py first to produce one."
        )

    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def load_event_context(filename: str = None) -> Optional[str]:
    resolved_name = filename or os.getenv("EVENT_CONTEXT_FILE", DEFAULT_EVENT_CONTEXT_FILENAME)
    context_path = _SCRIPT_DIR / resolved_name

    if not context_path.exists():
        return None

    try:
        with open(context_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    except Exception:
        return None

    if not content:
        return None

    if len(content) > _MAX_EVENT_CONTEXT_CHARS:
        content = content[:_MAX_EVENT_CONTEXT_CHARS] + "\n[TRUNCATED -- event_context.txt too long]"

    return content


def load_ioc_list(filename: str = None) -> Set[str]:
    """Optional analyst-supplied IOC list for cheap deterministic cross-
    referencing (e.g. by the Network Socket Correlator) -- one IP/domain per
    line, '#' comments and blank lines ignored. Lives at the repo root next to
    event_context.txt; absent by default, never required."""
    resolved_name = filename or os.getenv("IOC_LIST_FILE", DEFAULT_IOC_LIST_FILENAME)
    ioc_path = _SCRIPT_DIR / resolved_name

    if not ioc_path.exists():
        return set()

    try:
        with open(ioc_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return set()

    iocs: Set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        iocs.add(stripped.lower())
    return iocs
