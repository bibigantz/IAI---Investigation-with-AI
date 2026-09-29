"""
Network Socket Correlator -- pure automation, zero LLM tokens.

Runs windows.netscan.NetScan, normalizes every row into a NetworkConnection,
and flags sockets using a fixed deterministic rule set: known-suspicious
process/port combinations, listening on non-standard high ports, and
optional cross-referencing against an analyst-supplied IOC list
(core.utils.load_ioc_list). Orphan endpoints (owner PID no longer live per
pslist) are reported separately since a dead-owner socket is a timing
artifact, not necessarily malicious on its own.
"""
import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_agent import BaseHITLAgent
from core.models import NetworkConnection, SocketAnomaly, SocketCorrelation
from core.utils import load_ioc_list, locate_staging_directory
from . import volatility_runner as vol

AGENT_NAME = "Network_Socket_Correlator"

# Processes that have no legitimate reason to originate outbound traffic on a
# typical Windows host -- any foreign connection from one of these is
# automatically flagged regardless of port.
_UNEXPECTED_NETWORK_PROCESSES = {
    "notepad.exe", "calc.exe", "lsass.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "explorer.exe", "mspaint.exe",
}

# Ports commonly associated with C2 frameworks / reverse shells in the wild.
_SUSPICIOUS_PORTS = {4444, 1337, 6666, 6667, 31337, 8081, 9001, 9999}

_HIGH_PORT_THRESHOLD = 49152  # start of the dynamic/ephemeral range


def _first(row: Dict[str, Any], *keys: str, default=None):
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return default


def _as_int(value) -> Optional[int]:
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _normalize_netscan_rows(rows: List[Dict[str, Any]]) -> List[NetworkConnection]:
    connections = []
    for row in rows:
        connections.append(NetworkConnection(
            protocol=str(_first(row, "Proto", "Protocol", default="TCP")),
            local_addr=_first(row, "LocalAddr", "Local Addr"),
            local_port=_as_int(_first(row, "LocalPort", "Local Port")),
            foreign_addr=_first(row, "ForeignAddr", "Foreign Addr"),
            foreign_port=_as_int(_first(row, "ForeignPort", "Foreign Port")),
            state=_first(row, "State"),
            pid=_as_int(_first(row, "PID", "Pid")),
            owner_process=_first(row, "Owner", "Process"),
            created_utc=_first(row, "Created"),
        ))
    return connections


def correlate_sockets(
    netscan_rows: List[Dict[str, Any]],
    live_pids: set,
    ioc_set: Optional[set] = None,
) -> SocketCorrelation:
    """Pure function -- no I/O, trivially unit-testable."""
    ioc_set = ioc_set or set()
    connections = _normalize_netscan_rows(netscan_rows)
    flagged: List[SocketAnomaly] = []
    orphans: List[NetworkConnection] = []

    for conn in connections:
        process_name = (conn.owner_process or "").lower()
        reasons = []

        if process_name in _UNEXPECTED_NETWORK_PROCESSES and conn.foreign_addr:
            reasons.append(f"'{conn.owner_process}' has no legitimate reason to hold an outbound connection")

        if conn.foreign_port in _SUSPICIOUS_PORTS or conn.local_port in _SUSPICIOUS_PORTS:
            reasons.append("Port commonly associated with C2 frameworks / reverse shells")

        if conn.state and conn.state.upper() == "LISTENING" and conn.local_port and conn.local_port >= _HIGH_PORT_THRESHOLD:
            reasons.append(f"Listening on a non-standard high port ({conn.local_port})")

        if conn.foreign_addr and conn.foreign_addr.lower() in ioc_set:
            reasons.append(f"Foreign address {conn.foreign_addr} matches the analyst IOC list")

        if reasons:
            severity = "High" if any("IOC list" in r or "C2" in r for r in reasons) else "Medium"
            flagged.append(SocketAnomaly(connection=conn, reason="; ".join(reasons), severity=severity))

        if conn.pid is not None and conn.pid not in live_pids:
            orphans.append(conn)

    return SocketCorrelation(
        total_connections=len(connections),
        flagged_sockets=flagged,
        orphan_endpoints=orphans,
    )


class NetworkSocketCorrelatorAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=(
                "Deterministic rule-engine agent -- this system prompt is unused. "
                "See agents/memory_analysis/network.py:correlate_sockets()."
            ),
            include_event_context=False,
        )

    async def process_task(self, staging_root: Path):
        image_path = vol.locate_memory_image(staging_root)
        if image_path is None:
            deterministic_analysis = {
                "agent_name": self.agent_name,
                "status": "Clean",
                "anomalies_found": [],
                "summary": "No memory image found under MemoryDumps/raw/ -- socket correlation skipped.",
            }
            return await self.run_automated_with_hitl(
                parsed_tool_data={"error": "no memory image staged"},
                deterministic_analysis=deterministic_analysis,
            )

        netscan_rows = vol.run_plugin(image_path, "windows.netscan.NetScan")
        pslist_rows = vol.run_plugin(image_path, "windows.pslist.PsList")
        live_pids = {_as_int(_first(r, "PID", "Pid")) for r in pslist_rows} - {None}
        ioc_set = load_ioc_list()

        result = correlate_sockets(netscan_rows, live_pids, ioc_set)

        anomalies_found = [
            {
                "filepath": f"{a.connection.protocol} {a.connection.local_addr}:{a.connection.local_port} -> "
                            f"{a.connection.foreign_addr}:{a.connection.foreign_port} (PID {a.connection.pid}, "
                            f"{a.connection.owner_process})",
                "anomaly_type": "Suspicious Network Socket",
                "severity": a.severity,
                "justification": a.reason,
                "recommended_action": "Review process/connection; consider isolating host if IOC-matched",
            }
            for a in result.flagged_sockets
        ]
        status = "Clean"
        if any(a.severity == "High" for a in result.flagged_sockets):
            status = "Critical"
        elif result.flagged_sockets:
            status = "Suspicious"

        deterministic_analysis = {
            "agent_name": self.agent_name,
            "status": status,
            "anomalies_found": anomalies_found,
            "summary": (
                f"{result.total_connections} connection(s) observed, {len(result.flagged_sockets)} flagged, "
                f"{len(result.orphan_endpoints)} orphaned (owner PID no longer live)."
            ),
        }

        parsed_tool_data = {
            "memory_image": str(image_path),
            "socket_correlation": result.dict(),
        }

        return await self.run_automated_with_hitl(
            parsed_tool_data=parsed_tool_data,
            deterministic_analysis=deterministic_analysis,
        )


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = NetworkSocketCorrelatorAgent()
    asyncio.run(agent.process_task(staging_root))
