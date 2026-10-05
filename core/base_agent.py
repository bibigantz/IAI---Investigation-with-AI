import os
import json
import csv
import io
import hashlib
import subprocess
import xml.etree.ElementTree as ET
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from openai import AsyncOpenAI
from pydantic import BaseModel

from .models import AgentAnalysisReport, AgentResponse, HumanFeedback, FileMetadataRecord
from .utils import load_event_context


class BaseHITLAgent:
    def __init__(self, agent_name: str, system_prompt: str, include_event_context: bool = True,
                 event_context_filename: Optional[str] = None):
        self.agent_name = agent_name

        override_prompt = None
        try:
            from bridge.hitl_bridge import bridge
            override_prompt = bridge.prompt_overrides.get(agent_name)
        except Exception:
            pass
        self.system_prompt = override_prompt or system_prompt

        event_context = load_event_context(event_context_filename) if include_event_context else None
        self.event_context = event_context

        prompt_parts = [self.system_prompt]

        if event_context:
            prompt_parts.append(
                "=== CASE / EVENT CONTEXT (provided by the analyst, applies to ALL agents) ===\n"
                f"{event_context}\n"
                "Use this context to prioritize what you look for, but still report findings strictly "
                "from the parsed data you are given -- do not assume something is present just because "
                "the context mentions it."
            )

        prompt_parts.append(
            "You must output your analysis in strictly valid JSON matching this schema:\n"
            f"{AgentAnalysisReport.schema_json()}"
        )

        self.full_system_prompt = "\n\n".join(prompt_parts)
        self.conversation_history: List[Dict[str, str]] = [
            {"role": "system", "content": self.full_system_prompt}
        ]

        from .llm_config import get_active_llm_config
        llm_config = get_active_llm_config()
        self.llm_client = AsyncOpenAI(
            api_key=llm_config["api_key"],
            base_url=llm_config["base_url"],
        )
        self.model_name = llm_config["model_name"]
        self.MAX_PAYLOAD_CHARS = llm_config["context_limit"]

    def get_target_directory(self, base_staging_path: str, sub_path_parts: List[str]) -> Path:
        target_path = Path(base_staging_path).joinpath(*sub_path_parts)
        if not target_path.exists():
            try:
                target_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                pass
        return target_path

    def _calculate_file_hashes(self, filepath: Path) -> Dict[str, str]:
        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher_md5.update(buf)
                    hasher_sha256.update(buf)
                    buf = f.read(65536)
            return {"md5": hasher_md5.hexdigest(), "sha256": hasher_sha256.hexdigest()}
        except Exception:
            return {"error": "Permission denied or file locked"}

    _EXECUTABLE_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv"
    }

    _BINARY_ARTIFACT_EXTENSIONS = {
        ".dat", ".hve", ".evtx", ".db", ".pf", ".lnk", ".zip", ".rar", ".7z",
        ".iso", ".img", ".bin"
    }

    def _looks_like_binary(self, filepath: Path, sniff_bytes: int = 4096) -> bool:
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(sniff_bytes)
            if not chunk:
                return False
            if chunk.startswith(b"MZ"):
                return True
            if b"\x00" in chunk:
                return True
            nontext = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
            return (nontext / len(chunk)) > 0.30
        except Exception:
            return True

    def _read_text_safely(self, filepath: Path, max_chars: int = 4000) -> Optional[str]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(max_chars + 1)
            if len(content) > max_chars:
                content = content[:max_chars] + "\n[TRUNCATED]"
            return content
        except Exception:
            return None

    def _inventory_raw_file(self, filepath: Path) -> Dict:
        entry: Dict[str, Any] = {
            "filename": filepath.name,
            "extension": filepath.suffix.lower(),
        }
        try:
            stats = filepath.stat()
            entry["size_bytes"] = stats.st_size
        except Exception as e:
            entry["stat_error"] = str(e)
            return entry

        ext = entry["extension"]
        is_executable = ext in self._EXECUTABLE_EXTENSIONS
        is_known_binary_artifact = ext in self._BINARY_ARTIFACT_EXTENSIONS
        entry["is_executable"] = is_executable

        if stats.st_size < 50_000_000:
            entry.update(self._calculate_file_hashes(filepath))

        if is_executable or is_known_binary_artifact:
            entry["content_read"] = False
            entry["reason"] = "Executable/binary artifact -- listed only, not opened or reversed."
            return entry

        if self._looks_like_binary(filepath):
            entry["content_read"] = False
            entry["reason"] = "Binary content detected on inspection -- listed only."
            return entry

        content = self._read_text_safely(filepath)
        if content is not None:
            entry["content_read"] = True
            entry["content"] = content
        else:
            entry["content_read"] = False
            entry["reason"] = "Unreadable as text."

        return entry

    def _get_file_timestamps(self, filepath: Path) -> Dict[str, Optional[str]]:
        """Creation/modified/accessed timestamps as ISO-8601 UTC strings.

        On Windows, os.stat().st_ctime is the true filesystem creation time
        (unlike POSIX, where it is metadata-change time) -- correct semantics
        for this forensic use case.
        """
        try:
            stats = filepath.stat()
        except Exception:
            return {"created_utc": None, "modified_utc": None, "accessed_utc": None}

        def _iso(ts: float) -> Optional[str]:
            try:
                return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except Exception:
                return None

        return {
            "created_utc": _iso(stats.st_ctime),
            "modified_utc": _iso(stats.st_mtime),
            "accessed_utc": _iso(stats.st_atime),
        }

    _SIGNATURE_STATUS_MAP = {
        "Valid": "Signed-Valid",
        "NotSigned": "Unsigned",
        "HashMismatch": "Signed-Invalid",
        "NotTrusted": "Signed-Invalid",
        "UnknownError": "CheckFailed",
    }

    def _check_digital_signature(self, filepath: Path, timeout: int = 8) -> Dict[str, Optional[str]]:
        """Authenticode signature check via PowerShell's Get-AuthenticodeSignature.

        Filenames of collected artifacts are attacker-controlled data (they come
        from a possibly-malicious filesystem), so the path is passed inside a
        single-quoted PowerShell string literal with embedded single quotes
        doubled -- the standard PowerShell escape -- rather than interpolated
        into a double-quoted string, to prevent command/expression injection
        via a crafted filename.
        """
        try:
            safe_path = str(filepath).replace("'", "''")
            ps_script = (
                f"$s = Get-AuthenticodeSignature -LiteralPath '{safe_path}'; "
                "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject -replace \"`r`n\", ' ' } else { '' }; "
                "Write-Output ($s.Status.ToString() + '|' + $subj)"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                return {"signature_status": "CheckFailed", "signature_subject": None}
            output = result.stdout.strip()
            status_raw, _, subject = output.partition("|")
            return {
                "signature_status": self._SIGNATURE_STATUS_MAP.get(status_raw, status_raw or "CheckFailed"),
                "signature_subject": subject.strip() or None,
            }
        except Exception:
            return {"signature_status": "CheckFailed", "signature_subject": None}

    def build_file_metadata_records(
        self,
        raw_dir: Path,
        max_signature_checks: int = 25,
    ) -> List[FileMetadataRecord]:
        """Walk raw_dir and build a fully-typed, schema-validated FileMetadataRecord
        per file: full path, timestamps, hashes, and (bounded) digital signature
        status. Reuses _inventory_raw_file()'s executable/binary safe-read gate.
        """
        records: List[FileMetadataRecord] = []
        if not raw_dir.exists():
            return records

        signature_checks_used = 0
        for root, _, files in os.walk(raw_dir):
            for fname in files:
                fpath = Path(root) / fname
                base = self._inventory_raw_file(fpath)
                timestamps = self._get_file_timestamps(fpath)

                is_executable = bool(base.get("is_executable"))
                signature_status = "NotApplicable"
                signature_subject = None
                if is_executable:
                    if signature_checks_used < max_signature_checks:
                        sig = self._check_digital_signature(fpath)
                        signature_status = sig["signature_status"]
                        signature_subject = sig["signature_subject"]
                        signature_checks_used += 1
                    else:
                        signature_status = "NotChecked"

                records.append(FileMetadataRecord(
                    filename=base.get("filename", fname),
                    full_path=str(fpath),
                    extension=base.get("extension", fpath.suffix.lower()),
                    size_bytes=base.get("size_bytes", 0) or 0,
                    created_utc=timestamps["created_utc"],
                    modified_utc=timestamps["modified_utc"],
                    accessed_utc=timestamps["accessed_utc"],
                    md5=base.get("md5"),
                    sha256=base.get("sha256"),
                    is_executable=is_executable,
                    signature_status=signature_status,
                    signature_subject=signature_subject,
                    content_read=bool(base.get("content_read")),
                    content_preview=base.get("content") if base.get("content_read") else None,
                    note=base.get("reason") or base.get("stat_error"),
                ))
        return records

    def write_records_csv(self, records: List[BaseModel], csv_path: Path) -> None:
        """Serialize a list of Pydantic records to CSV. Silently no-ops on an
        empty list or an unwritable path -- CSV export is a convenience
        artifact, never a requirement for the LLM analysis path to proceed."""
        if not records:
            return
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            fieldnames = list(records[0].dict().keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in records:
                    writer.writerow(r.dict())
        except Exception:
            pass

    def build_malware_path_payload(
        self,
        staging_root: Path,
        category: str,
        max_signature_checks: int = 25,
    ) -> str:
        """Structured, Pydantic-validated replacement for parse_category_artifacts()
        aimed at high-risk execution-path categories (Temp, Downloads, AppData,
        Public). Every raw/ file becomes a FileMetadataRecord (full path,
        created/modified/accessed timestamps, md5+sha256, executable flag,
        digital-signature status); the inventory is persisted as both CSV and
        JSON, and the JSON is what gets handed to the LLM.
        """
        category_path = staging_root / category
        raw_dir = category_path / "raw"
        meta_dir = category_path / "metadata"

        records = self.build_file_metadata_records(raw_dir, max_signature_checks=max_signature_checks)
        # Preserve any pre-existing metadata/ content (e.g. a directory manifest
        # written by the collector) before we add our own inventory CSV to it.
        existing_metadata = self._read_metadata_dir(meta_dir)

        if records:
            meta_dir.mkdir(parents=True, exist_ok=True)
            self.write_records_csv(records, meta_dir / f"{category}_file_inventory.csv")

        payload: Dict[str, Any] = {
            "category": category,
            "category_path": str(category_path),
            "file_count": len(records),
            "files": [r.dict() for r in records],
            "metadata": existing_metadata,
        }
        if not category_path.exists():
            payload["error"] = f"Category folder not found: {category_path}"
        elif not raw_dir.exists():
            payload["raw_inventory_note"] = f"No raw/ folder present under {category_path}"

        return self._truncate_payload(json.dumps(payload, default=str))

    def _read_metadata_dir(
        self,
        meta_dir: Path,
        metadata_row_filter: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """Read every file under a category's metadata/ folder: CSV files become
        row lists (optionally keyword-filtered), everything else (tool logs,
        JSON manifests, etc.) is read as truncated text."""
        entries: List[Dict[str, Any]] = []
        if not meta_dir.exists():
            return entries

        for root, _, files in os.walk(meta_dir):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                meta_entry: Dict[str, Any] = {"filename": fname}

                if ext == ".csv":
                    rows = []
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                if metadata_row_filter:
                                    cols = metadata_row_filter.get("columns", [])
                                    keywords = [k.lower() for k in metadata_row_filter.get("keywords", [])]
                                    haystack = " ".join(str(row.get(c, "")) for c in cols).lower()
                                    if not any(kw in haystack for kw in keywords):
                                        continue
                                rows.append(row)
                        meta_entry["rows"] = rows
                        meta_entry["row_count"] = len(rows)
                    except Exception as e:
                        meta_entry["error"] = f"CSV parse error: {e}"
                else:
                    content = self._read_text_safely(fpath, max_chars=6000)
                    meta_entry["content"] = content if content is not None else "[unreadable]"

                entries.append(meta_entry)
        return entries

    def parse_category_artifacts(
        self,
        staging_root: Path,
        category: str,
        metadata_row_filter: Optional[Dict[str, List[str]]] = None,
    ) -> str:
        category_path = staging_root / category
        raw_dir = category_path / "raw"
        meta_dir = category_path / "metadata"

        result: Dict[str, Any] = {
            "category": category,
            "category_path": str(category_path),
            "raw_inventory": [],
            "metadata": [],
        }

        if not category_path.exists():
            result["error"] = f"Category folder not found: {category_path}"
            return self._truncate_payload(json.dumps(result))

        if raw_dir.exists():
            for root, _, files in os.walk(raw_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    result["raw_inventory"].append(self._inventory_raw_file(fpath))
        else:
            result["raw_inventory_note"] = f"No raw/ folder present under {category_path}"

        if meta_dir.exists():
            result["metadata"] = self._read_metadata_dir(meta_dir, metadata_row_filter)
        else:
            result["metadata_note"] = f"No metadata/ folder present under {category_path}"

        return self._truncate_payload(json.dumps(result))

    def parse_directory_to_json(self, target_path: Path, include_hashes: bool = False) -> str:
        if not target_path.exists() or not target_path.is_dir():
            return json.dumps({"error": f"Directory not found or is not a folder: {target_path}"})

        extracted_files = []
        for root, _, files in os.walk(target_path):
            for file in files:
                filepath = Path(root) / file
                try:
                    stats = filepath.stat()
                    file_data = {
                        "filename": file,
                        "relative_path": str(filepath.relative_to(target_path)),
                        "size_bytes": stats.st_size,
                        "extension": filepath.suffix.lower()
                    }
                    if include_hashes and stats.st_size < 50000000:
                        file_data.update(self._calculate_file_hashes(filepath))
                    extracted_files.append(file_data)
                except Exception as e:
                    extracted_files.append({"filename": file, "error": str(e)})

        payload = json.dumps({"target_path": str(target_path), "files": extracted_files})
        return self._truncate_payload(payload)

    def parse_csv_to_json(self, csv_path: Path) -> str:
        if not csv_path.exists():
            return json.dumps({"error": f"CSV file not found: {csv_path}"})

        data = []
        try:
            with open(csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
        except Exception as e:
            return json.dumps({"error": f"CSV Parse error: {e}"})

        payload = json.dumps({"source_csv": csv_path.name, "rows": data})
        return self._truncate_payload(payload)

    def parse_xml_tasks_to_json(self, tasks_dir: Path) -> str:
        if not tasks_dir.exists() or not tasks_dir.is_dir():
            return json.dumps({"error": f"Tasks directory not found: {tasks_dir}"})

        tasks_data = []
        for xml_file in tasks_dir.glob("**/*.xml"):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()

                for elem in root.iter():
                    if '}' in elem.tag:
                        elem.tag = elem.tag.split('}', 1)[1]

                exec_action = root.find(".//Exec")
                if exec_action is not None:
                    command = exec_action.findtext("Command", default="")
                    args = exec_action.findtext("Arguments", default="")
                    tasks_data.append({
                        "task_name": xml_file.name,
                        "command": command,
                        "arguments": args,
                        "author": root.findtext(".//Author", default="Unknown")
                    })
            except Exception as e:
                tasks_data.append({"task_name": xml_file.name, "error": str(e)})

        payload = json.dumps({"scheduled_tasks": tasks_data})
        return self._truncate_payload(payload)

    def _truncate_payload(self, payload: str) -> str:
        if len(payload) > self.MAX_PAYLOAD_CHARS:
            warning = f"\n\n[WARNING: Data truncated. Original length {len(payload)} chars, truncated to {self.MAX_PAYLOAD_CHARS} chars.]"
            return payload[:self.MAX_PAYLOAD_CHARS] + warning
        return payload

    async def execute_llm_analysis(self, data_context: str) -> Dict:
        try:
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=self.conversation_history,
                response_format={"type": "json_object"},
                temperature=0.1
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"error": "Failed to generate analysis", "raw_exception": str(e)}

    async def send_to_dashboard_and_wait(self, response_payload: AgentResponse) -> HumanFeedback:
        try:
            from bridge.hitl_bridge import bridge
            bridge.agent_states[self.agent_name] = response_payload.dict()

            if bridge.execution_mode == "AUTOMATIC":
                bridge.log_event(self.agent_name, "Auto-approving (AUTOMATIC mode)", level="INFO")
                bridge.update_node_state(self.agent_name, "BLUE")
                return HumanFeedback(action="APPROVE")

            event = bridge.register_hitl_pause(
                agent_name=self.agent_name,
                raw_data_parsed=response_payload.raw_data_parsed,
                ai_analysis=response_payload.ai_analysis
            )

            await event.wait()

            record = bridge.pending_approvals.pop(self.agent_name, {})
            decision = record.get("decision", {"action": "APPROVE"})
            return HumanFeedback(action=decision.get("action", "APPROVE"), feedback=decision.get("feedback"))
        except Exception as e:
            action = input(f"[{self.agent_name}] Human action (APPROVE/REVISE): ").strip().upper()
            if action == "REVISE":
                feedback = input(f"[{self.agent_name}] Enter instructions for the LLM: ")
                return HumanFeedback(action="REVISE", feedback=feedback)
            return HumanFeedback(action="APPROVE")

    async def _run_fast_pass_triage(self, parsed_tool_data: Any) -> Optional[Dict[str, Any]]:
        """Optional local "System One" pre-filter (core/triage_engine.py), run
        ahead of the deep generative LLM call. Returns None when the feature
        is disabled OR the local triage service is unreachable/times out --
        in both cases the caller proceeds exactly as if this feature didn't
        exist, satisfying the "Graceful Fallback" / zero-disruption
        requirement. Never raises.
        """
        try:
            from core import triage_engine
            from bridge.hitl_bridge import bridge
        except Exception:
            return None

        config = triage_engine.get_triage_config()
        if not config.get("enabled"):
            return None

        staging_dir = getattr(bridge, "active_investigation_id", None)

        try:
            verdict = await triage_engine.evaluate_severity(str(parsed_tool_data), self.agent_name, config)
        except triage_engine.TriageUnavailableError as e:
            bridge.log_event(
                self.agent_name,
                f"Fast-pass triage service unreachable ({e}) -- falling back to standard deep analysis.",
                level="WARN",
            )
            return None
        except Exception:
            return None

        threshold = float(config.get("severity_threshold", 0.8))
        route_to_deep = verdict["severity_score"] >= threshold
        triage_engine.log_triage_decision(
            staging_dir, self.agent_name, verdict["severity_score"], verdict["severity_label"],
            verdict["summary"], "routed_high_severity" if route_to_deep else "suppressed",
            str(parsed_tool_data),
        )
        bridge.log_event(
            self.agent_name,
            f"Fast-pass triage: {verdict['severity_label']} ({verdict['severity_score']:.2f}) -- "
            + ("routing to deep analysis." if route_to_deep else "suppressed from deep LLM analysis (below threshold)."),
            level="INFO",
        )

        result: Dict[str, Any] = {
            "route_to_deep_analysis": route_to_deep,
            "severity_score": verdict["severity_score"],
            "severity_label": verdict["severity_label"],
            "summary": verdict["summary"],
        }
        if route_to_deep:
            result["metadata_note"] = (
                f"[FAST-PASS TRIAGE PRE-FILTER RESULT: severity={verdict['severity_label']} "
                f"(score {verdict['severity_score']:.2f}) -- {verdict['summary'] or 'no summary provided'}. "
                "This flagged the artifact for full deep analysis; use it as context, not a substitute "
                "for your own independent analysis.]"
            )
        else:
            result["suppressed_analysis"] = {
                "agent_name": self.agent_name,
                "status": "Suspicious" if verdict["severity_label"] == "Medium" else "Clean",
                "anomalies_found": [] if verdict["severity_label"] == "Low" else [{
                    "filepath": "N/A",
                    "anomaly_type": "Fast-Pass Triage Flag",
                    "severity": verdict["severity_label"],
                    "justification": verdict["summary"] or "Local fast-pass triage model flagged this as worth a second look.",
                    "recommended_action": "Click Revise to request a full deep LLM analysis if this needs further review.",
                }],
                "summary": (
                    f"[FAST-PASS TRIAGE -- {verdict['severity_label']} severity ({verdict['severity_score']:.2f}), "
                    "below the configured threshold, so generative deep analysis was skipped to save tokens. "
                    f"{verdict['summary']} Approve to accept this fast-pass result, or Revise to request a full "
                    "deep LLM re-analysis.]"
                ),
            }
        return result

    async def run_with_hitl(self, parsed_tool_data: Any) -> AgentResponse:
        try:
            from bridge.hitl_bridge import bridge
            await bridge.wait_if_paused()
        except Exception:
            pass

        triage_result = await self._run_fast_pass_triage(parsed_tool_data)
        fast_pass_suppressed = bool(triage_result) and not triage_result["route_to_deep_analysis"]

        self.conversation_history.append({
            "role": "user",
            "content": f"Analyze this newly extracted forensic data:\n{parsed_tool_data}"
        })
        if triage_result and triage_result["route_to_deep_analysis"]:
            self.conversation_history.append({"role": "user", "content": triage_result["metadata_note"]})

        while True:
            if fast_pass_suppressed:
                ai_conclusion_dict = triage_result["suppressed_analysis"]
            else:
                ai_conclusion_dict = await self.execute_llm_analysis(parsed_tool_data)

            current_state = AgentResponse(
                agent_name=self.agent_name,
                raw_data_parsed=parsed_tool_data,
                ai_analysis=ai_conclusion_dict
            )

            human_decision = await self.send_to_dashboard_and_wait(current_state)

            if human_decision.action == "APPROVE":
                current_state.status = "APPROVED"
                return current_state

            elif human_decision.action == "REVISE":
                if fast_pass_suppressed:
                    # Analyst explicitly requested a full deep analysis of a
                    # fast-pass-suppressed finding -- this IS the "explicitly
                    # requested via the UI / HITL queue" escalation path,
                    # reusing the existing Approve/Revise HITL controls rather
                    # than a separate queue UI.
                    fast_pass_suppressed = False
                    try:
                        from core import triage_engine
                        from bridge.hitl_bridge import bridge
                        staging_dir = getattr(bridge, "active_investigation_id", None)
                        triage_engine.log_triage_decision(
                            staging_dir, self.agent_name, triage_result["severity_score"],
                            triage_result["severity_label"], triage_result["summary"], "escalated",
                        )
                        bridge.log_event(
                            self.agent_name,
                            "Analyst escalated a fast-pass-suppressed finding to full deep analysis.",
                            level="HITL",
                        )
                    except Exception:
                        pass
                    feedback_note = f" Analyst note: {human_decision.feedback}" if human_decision.feedback else ""
                    self.conversation_history.append({
                        "role": "user",
                        "content": (
                            "Analyst requested a full deep analysis of this fast-pass-suppressed artifact "
                            f"(originally scored {triage_result['severity_score']:.2f}, "
                            f"{triage_result['severity_label']})."
                            f"{feedback_note} Perform complete forensic analysis now and return updated JSON."
                        )
                    })
                else:
                    self.conversation_history.append({"role": "assistant", "content": json.dumps(ai_conclusion_dict)})
                    self.conversation_history.append({
                        "role": "user",
                        "content": f"Human Analyst Override: {human_decision.feedback}. Fix your analysis and return updated JSON."
                    })

    async def run_automated_with_hitl(self, parsed_tool_data: Any, deterministic_analysis: Dict) -> AgentResponse:
        """HITL loop for pure-automation agents (deterministic correlation/rule
        engines, e.g. the Network Socket Correlator and MALFIND Correlator) that
        must never spend an LLM call producing their analysis. `deterministic_analysis`
        already matches the AgentAnalysisReport shape (status/anomalies_found/summary)
        and is submitted to the dashboard/HITL queue exactly like an LLM result would be.

        REVISE has no LLM to hand feedback to -- there is nothing to regenerate from
        rules alone -- so a revision request is logged as an analyst annotation and the
        same deterministic result is re-submitted for another decision, unchanged.
        """
        try:
            from bridge.hitl_bridge import bridge
            await bridge.wait_if_paused()
        except Exception:
            pass

        while True:
            current_state = AgentResponse(
                agent_name=self.agent_name,
                raw_data_parsed=parsed_tool_data,
                ai_analysis=deterministic_analysis
            )

            human_decision = await self.send_to_dashboard_and_wait(current_state)

            if human_decision.action == "APPROVE":
                current_state.status = "APPROVED"
                return current_state

            elif human_decision.action == "REVISE":
                try:
                    from bridge.hitl_bridge import bridge
                    bridge.log_event(
                        self.agent_name,
                        f"Analyst annotation on automated result (no LLM to re-derive it from): {human_decision.feedback}",
                        level="HITL"
                    )
                except Exception:
                    pass
