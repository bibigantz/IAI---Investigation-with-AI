"""Background retention policy checker.

Turns the Management page's "auto-archive" policy toggle from a stored-but-
inert checkbox into something that actually runs automatically: on a timer,
every category with auto_archive_enabled=True gets checked against its
policy, and a violation is logged (visible in the live log terminal and the
global audit log) the moment it's newly detected.

Deliberately does NOT delete anything automatically -- that stays a manual
preview-then-confirm action on the Retention page, on purpose. Automating
irreversible deletion of forensic evidence unattended is a different,
much riskier feature than "notice a policy violation automatically," and
this module only builds the latter.
"""
import threading
import time
from typing import Dict

_last_flagged_counts: Dict[str, int] = {}
_lock = threading.Lock()


def check_policies_once(project_root: str) -> Dict[str, int]:
    """Runs one check pass; returns {category: newly-logged violation count}
    for whichever categories had a change worth logging. Exposed as its own
    function (rather than only the background loop) so it's directly
    testable without waiting for the timer."""
    from db.database import get_session
    from db.models import RetentionPolicy
    from bridge.hitl_bridge import bridge
    from . import retention

    with get_session() as session:
        policies = session.query(RetentionPolicy).filter(RetentionPolicy.auto_archive_enabled == True).all()  # noqa: E712
        policy_data = [(p.category, p.max_age_days, p.max_total_gb) for p in policies]

    newly_logged = {}
    with _lock:
        for category, max_age_days, max_total_gb in policy_data:
            if max_age_days is None and max_total_gb is None:
                continue
            candidates = retention.preview_sweep(project_root, category, max_age_days, max_total_gb)
            count = len(candidates)
            previous = _last_flagged_counts.get(category)
            if count > 0 and count != previous:
                total_gb = sum(c["size_bytes"] for c in candidates) / (1024 ** 3)
                bridge.log_event(
                    "RETENTION",
                    f"Auto-flag: {count} file(s) in '{category}' now violate the active retention policy "
                    f"({total_gb:.2f} GB total). Review and confirm deletion from "
                    f"Management -> Data Lifecycle & Retention -- nothing is deleted automatically.",
                    level="WARN",
                )
                newly_logged[category] = count
            _last_flagged_counts[category] = count
    return newly_logged


def start_background_checker(project_root: str, interval_seconds: int = 600) -> threading.Thread:
    def loop():
        while True:
            try:
                check_policies_once(project_root)
            except Exception:
                pass  # a scheduler tick failing must never take the server down
            time.sleep(interval_seconds)

    thread = threading.Thread(target=loop, daemon=True, name="retention-policy-checker")
    thread.start()
    return thread
