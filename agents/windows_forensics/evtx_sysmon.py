import asyncio
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from Evtx.Evtx import Evtx

from core.base_agent import BaseHITLAgent
from core.models import CorrelatedSecurityEvent
from core.utils import locate_staging_directory
from core import sigma_engine

# The aggressive pre-filter: Event IDs are NOT globally unique -- e.g. EventID
# 1 means "Process Creation" for Sysmon but "System Time Changed" for the
# unrelated Kernel-General provider. Every allow-list entry is therefore keyed
# by (Provider Name, EventID), not EventID alone. Everything else (routine
# service telemetry, driver load noise, heartbeats, etc.) is dropped before
# anything reaches the LLM context window -- this is what keeps a 50k-event
# Security.evtx from blowing straight through MAX_PAYLOAD_CHARS.
ALLOWED_EVENTS: Dict[Tuple[str, int], str] = {
    ("Microsoft-Windows-Sysmon", 1): "Process Creation",
    ("Microsoft-Windows-Sysmon", 3): "Network Connection",
    ("Microsoft-Windows-Sysmon", 5): "Process Terminated",
    ("Microsoft-Windows-Sysmon", 11): "File Created",
    ("Service Control Manager", 7045): "Service Installed",
    ("Microsoft-Windows-Security-Auditing", 4624): "Logon Success",
    ("Microsoft-Windows-Security-Auditing", 4625): "Logon Failure",
    ("Microsoft-Windows-PowerShell", 4104): "PowerShell Script Block",
}


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def parse_evtx_file(
    evtx_path: Path,
    allowed_events: Optional[Dict[Tuple[str, int], str]] = None,
    max_events: int = 300,
) -> Tuple[List[CorrelatedSecurityEvent], Optional[str]]:
    """Stream one .evtx file record-by-record via python-evtx, keeping only
    events matching the pre-filtered (Provider, EventID) allow-list.
    Returns (events, error)."""
    allowed_events = allowed_events if allowed_events is not None else ALLOWED_EVENTS
    events: List[CorrelatedSecurityEvent] = []
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                if len(events) >= max_events:
                    break
                try:
                    root = ET.fromstring(record.xml())
                except Exception:
                    continue

                system_elem = None
                eventdata_elem = None
                for child in root:
                    tag = _strip_ns(child.tag)
                    if tag == "System":
                        system_elem = child
                    elif tag in ("EventData", "UserData"):
                        eventdata_elem = child
                if system_elem is None:
                    continue

                event_id: Optional[int] = None
                provider: Optional[str] = None
                time_created: Optional[str] = None
                channel: Optional[str] = None
                computer: Optional[str] = None
                for sc in system_elem:
                    tag = _strip_ns(sc.tag)
                    if tag == "EventID":
                        try:
                            event_id = int((sc.text or "").strip())
                        except ValueError:
                            event_id = None
                    elif tag == "Provider":
                        provider = sc.attrib.get("Name")
                    elif tag == "TimeCreated":
                        time_created = sc.attrib.get("SystemTime")
                    elif tag == "Channel":
                        channel = sc.text
                    elif tag == "Computer":
                        computer = sc.text

                if event_id is None or provider is None:
                    continue
                label = allowed_events.get((provider, event_id))
                if label is None:
                    continue

                key_fields: Dict[str, Any] = {}
                if eventdata_elem is not None:
                    for data in eventdata_elem:
                        name = data.attrib.get("Name")
                        value = data.text
                        if name:
                            key_fields[name] = value
                        elif value:
                            key_fields.setdefault("_data", []).append(value)

                events.append(CorrelatedSecurityEvent(
                    event_id=event_id,
                    provider=provider,
                    time_created_utc=time_created,
                    channel=channel,
                    computer=computer,
                    event_type_label=label,
                    key_fields=key_fields,
                    source_file=evtx_path.name,
                ))
    except Exception as e:
        return events, str(e)
    return events, None


def _evaluate_sigma_rules(events: List[CorrelatedSecurityEvent]) -> List[Dict[str, Any]]:
    """Runs every active Sigma rule (Management page -> Rule & Detection ->
    YARA & Sigma Rules) against each pre-filtered event's fields. See
    core/sigma_engine.py for exactly what subset of the Sigma spec this
    supports -- this is real execution, not a catalogue."""
    anomalies = []
    for event in events:
        if event.event_id == -1:  # parse-error placeholder, not a real event
            continue
        fields = dict(event.key_fields)
        fields.update({
            "EventID": event.event_id, "Provider": event.provider,
            "Channel": event.channel, "Computer": event.computer,
        })
        for match in sigma_engine.evaluate_event(fields):
            anomalies.append({
                "filepath": event.source_file,
                "anomaly_type": f"Sigma Match: {match['rule_name']}",
                "severity": "High",
                "justification": (
                    f"Event {event.event_id} ({event.event_type_label}) at "
                    f"{event.time_created_utc or 'unknown time'} matched Sigma rule '{match['rule_name']}'."
                ),
                "recommended_action": "Review the matched event in its source .evtx file and correlate with the timeline.",
            })
    return anomalies


class EvtxSysmonAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="EVTX_Sysmon_Correlator",
            system_prompt=(
                "You are an Incident Responder specializing in Windows Event Log (EVTX) and Sysmon analysis. "
                "You are given a pre-filtered, chronologically-ordered list of high-value events -- ONLY "
                "process creation (ID 1), network connection (ID 3), process termination (ID 5), file "
                "creation (ID 11), service installation (ID 7045), logon success/failure (ID 4624/4625), "
                "and PowerShell script block logging (ID 4104) survive the pre-filter; routine OS noise has "
                "already been stripped out before reaching you. "
                "Correlate events across the timeline to identify attack chains, e.g.: repeated 4625 logon "
                "failures from the same source followed by a 4624 success (brute force), a 4624 immediately "
                "followed by an unexpected process creation (post-compromise execution), a process creation "
                "followed by an outbound network connection to an unusual port (C2 beacon), or a service "
                "installation (7045) with a suspicious ImagePath (persistence). "
                "Reference each finding by its timestamp and event_id so the analyst can jump to that record."
            )
        )

    def _load_allowed_events(self, staging_root: Path, max_events_per_file: int = 300, max_total: int = 400) -> List[CorrelatedSecurityEvent]:
        raw_dir = staging_root / "Logs" / "raw"
        all_events: List[CorrelatedSecurityEvent] = []
        if not raw_dir.exists():
            return all_events

        for evtx_path in sorted(raw_dir.glob("*.evtx")):
            events, error = parse_evtx_file(evtx_path, max_events=max_events_per_file)
            if error:
                all_events.append(CorrelatedSecurityEvent(
                    event_id=-1,
                    event_type_label="Parse Error",
                    source_file=evtx_path.name,
                    key_fields={"error": error},
                ))
                continue
            all_events.extend(events)

        # Chronological order (events without a timestamp sort last), then cap.
        all_events.sort(key=lambda e: e.time_created_utc or "9999")
        return all_events[:max_total]

    async def process_task(self, staging_root: Path):
        events = self._load_allowed_events(staging_root)

        meta_dir = staging_root / "Logs" / "metadata"
        if events:
            meta_dir.mkdir(parents=True, exist_ok=True)
            self.write_records_csv(events, meta_dir / "correlated_events.csv")

        # Fold in whatever EvtxECmd CSV metadata the collector already produced,
        # so the LLM also sees anything the tool-based parser surfaced.
        existing_metadata = self._read_metadata_dir(meta_dir)

        payload: Dict[str, Any] = {
            "category": "Logs",
            "category_path": str(staging_root / "Logs"),
            "correlated_event_count": len(events),
            "allowed_events": [
                {"provider": provider, "event_id": eid, "label": label}
                for (provider, eid), label in ALLOWED_EVENTS.items()
            ],
            "correlated_events": [e.dict() for e in events],
            "metadata": existing_metadata,
        }
        if not (staging_root / "Logs" / "raw").exists():
            payload["raw_inventory_note"] = "No Logs/raw/ folder present -- no .evtx files were collected."

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        response = await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        sigma_anomalies = _evaluate_sigma_rules(events)
        if sigma_anomalies:
            from bridge.hitl_bridge import bridge
            state = bridge.agent_states.get(self.agent_name)
            if state and isinstance(state.get("ai_analysis"), dict):
                existing = state["ai_analysis"].get("anomalies_found") or []
                state["ai_analysis"]["anomalies_found"] = list(existing) + sigma_anomalies
                bridge.save_snapshot(force=True)
            response.ai_analysis.setdefault("anomalies_found", [])
            response.ai_analysis["anomalies_found"] = list(response.ai_analysis["anomalies_found"]) + sigma_anomalies

        return response


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = EvtxSysmonAgent()
    asyncio.run(agent.process_task(staging_root))
