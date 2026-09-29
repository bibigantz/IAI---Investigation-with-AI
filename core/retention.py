"""Evidence storage scanning + retention sweep preview/execute.

Bucketed by file extension rather than by collector category folder name,
since memory dumps/PCAPs are analyst-uploaded (not produced by a dedicated
collector category) and can land under any category folder depending on how
they were uploaded -- extension is the reliable signal here, not path.

Deletion is always analyst-confirmed: preview_sweep() only lists candidates,
execute_sweep() only deletes the exact paths it's given (and re-validates
each one is really evidence under this project's own staging folders before
touching it) -- there is no unattended background sweep.
"""
import glob
import os
import time
from pathlib import Path
from typing import Any, Dict, List

_MEMORY_EXTENSIONS = {".raw", ".dmp", ".vmem", ".mem", ".img"}
_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

CATEGORIES = ("memory_dumps", "pcaps", "evidence_general")


def _categorize(ext: str) -> str:
    if ext in _MEMORY_EXTENSIONS:
        return "memory_dumps"
    if ext in _PCAP_EXTENSIONS:
        return "pcaps"
    return "evidence_general"


def _iter_investigation_files(project_root: str):
    for folder in glob.glob(os.path.join(project_root, "investigation_staging_*")):
        if not os.path.isdir(folder):
            continue
        folder_name = os.path.basename(folder)
        for root, _, files in os.walk(folder):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    stat = os.stat(fpath)
                except OSError:
                    continue
                yield folder_name, fpath, stat


def scan_storage_summary(project_root: str) -> Dict[str, Any]:
    totals = {cat: {"total_bytes": 0, "file_count": 0} for cat in CATEGORIES}
    by_investigation: Dict[str, Dict[str, Any]] = {}

    for folder_name, fpath, stat in _iter_investigation_files(project_root):
        ext = Path(fpath).suffix.lower()
        cat = _categorize(ext)
        totals[cat]["total_bytes"] += stat.st_size
        totals[cat]["file_count"] += 1

        inv = by_investigation.setdefault(folder_name, {"folder_name": folder_name, "total_bytes": 0, "mtime": stat.st_mtime})
        inv["total_bytes"] += stat.st_size
        inv["mtime"] = max(inv["mtime"], stat.st_mtime)

    return {
        "categories": totals,
        "by_investigation": sorted(by_investigation.values(), key=lambda i: i["total_bytes"], reverse=True),
    }


def preview_sweep(project_root: str, category: str, max_age_days: int = None, max_total_gb: float = None) -> List[Dict[str, Any]]:
    now = time.time()
    candidates = []
    for folder_name, fpath, stat in _iter_investigation_files(project_root):
        ext = Path(fpath).suffix.lower()
        if _categorize(ext) != category:
            continue
        age_days = (now - stat.st_mtime) / 86400
        candidates.append({
            "path": fpath, "investigation": folder_name, "size_bytes": stat.st_size,
            "age_days": round(age_days, 1), "reason": None,
        })

    flagged = []
    if max_age_days is not None:
        for c in candidates:
            if c["age_days"] > max_age_days:
                c["reason"] = f"older than {max_age_days} days"
                flagged.append(c)

    if max_total_gb is not None:
        max_bytes = max_total_gb * (1024 ** 3)
        remaining = [c for c in candidates if c not in flagged]
        remaining.sort(key=lambda c: c["age_days"], reverse=True)  # oldest first
        running_total = sum(c["size_bytes"] for c in candidates) - sum(c["size_bytes"] for c in flagged)
        for c in remaining:
            if running_total <= max_bytes:
                break
            c["reason"] = f"total category size exceeds {max_total_gb} GB quota"
            flagged.append(c)
            running_total -= c["size_bytes"]

    return flagged


def _is_safe_evidence_path(path: str, project_root: str) -> bool:
    root = os.path.abspath(project_root)
    candidate = os.path.abspath(path)
    if not candidate.startswith(root + os.sep):
        return False
    rel = os.path.relpath(candidate, root)
    top = rel.split(os.sep, 1)[0]
    return top.startswith("investigation_staging_") and os.path.isfile(candidate)


def execute_sweep(project_root: str, paths: List[str]) -> Dict[str, Any]:
    deleted, errors = [], []
    for path in paths:
        if not _is_safe_evidence_path(path, project_root):
            errors.append({"path": path, "error": "Rejected: not a recognized evidence file under an investigation_staging_* folder."})
            continue
        try:
            os.remove(path)
            deleted.append(path)
        except OSError as e:
            errors.append({"path": path, "error": str(e)})
    return {"deleted": deleted, "errors": errors}
