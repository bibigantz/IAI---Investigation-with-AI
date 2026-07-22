import os
import json
import sys
import glob
import asyncio
import hashlib
import csv
import io
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

# Prevent cp1252 encoding errors on Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# ==========================================
# 0. STAGING DIRECTORY RESOLUTION
# ==========================================
# collector_agent.py is the ONLY thing that creates the
# investigation_staging_<timestamp> folder tree. The analysis agents
# (master + sub-agents) should never invent or mkdir their own staging
# root -- they just need to find the one the collector already produced.

def locate_staging_directory(search_root: str = ".", explicit_path: Optional[str] = None) -> Path:
    """
    Resolves the investigation staging directory.

    - If explicit_path is given (e.g. passed on the CLI), that is used directly.
    - Otherwise, scans search_root for folders matching 'investigation_staging_*'
      (the pattern collector_agent.py uses) and returns the most recently
      created one.

    Raises FileNotFoundError if nothing is found, since analysis has nothing
    to run against without a real collector output folder.
    """
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

    # Most recently created/modified staging folder wins.
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]

# ==========================================
# 0b. EVENT / CASE CONTEXT LOADING
# ==========================================
# Lets an analyst drop a short brief into a txt file sitting next to the
# scripts (e.g. "what we know happened, what to look for") and have EVERY
# agent's system prompt automatically include it -- so all tools share the
# same case context instead of each one reasoning blind.

DEFAULT_EVENT_CONTEXT_FILENAME = "event_context.txt"
_SCRIPT_DIR = Path(__file__).resolve().parent
_MAX_EVENT_CONTEXT_CHARS = 4000

def load_event_context(filename: str = None) -> Optional[str]:
    """
    Reads the case/event context file from the same folder as this script
    (core_agents.py), NOT the current working directory. Returns the file's
    text, or None if no such file exists yet (this is expected/fine -- the
    file is optional; an analyst adds it when they have a lead).

    filename defaults to DEFAULT_EVENT_CONTEXT_FILENAME, but can be overridden
    per-call or via the EVENT_CONTEXT_FILE environment variable.
    """
    resolved_name = filename or os.getenv("EVENT_CONTEXT_FILE", DEFAULT_EVENT_CONTEXT_FILENAME)
    context_path = _SCRIPT_DIR / resolved_name

    if not context_path.exists():
        return None

    try:
        with open(context_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
    except Exception as e:
        print(f"[CORE] Failed to read event context file {context_path}: {e}")
        return None

    if not content:
        return None

    if len(content) > _MAX_EVENT_CONTEXT_CHARS:
        content = content[:_MAX_EVENT_CONTEXT_CHARS] + "\n[TRUNCATED -- event_context.txt too long]"

    return content

# ==========================================
# 1. DATA MODELS
# ==========================================

class ForensicAnomaly(BaseModel):
    filepath: str = Field(description="The full path of the suspicious artifact")
    anomaly_type: str = Field(description="E.g., 'Double Extension', 'Unsigned Binary', 'Suspicious Path'")
    severity: str = Field(description="High, Medium, or Low")
    justification: str = Field(description="Why this was flagged based on the parsed data")
    recommended_action: str = Field(description="What the HITL analyst should investigate next")

class AgentAnalysisReport(BaseModel):
    agent_name: str
    status: str = Field(description="Clean, Suspicious, or Critical")
    anomalies_found: List[ForensicAnomaly] = []
    summary: str = Field(description="A brief overview of the findings")

class AgentResponse(BaseModel):
    agent_name: str
    raw_data_parsed: Any
    ai_analysis: Dict
    status: str = "PENDING_APPROVAL"

class HumanFeedback(BaseModel):
    action: str
    feedback: Optional[str] = None

# ==========================================
# 2. BASE HITL AGENT
# ==========================================

class BaseHITLAgent:
    def __init__(self, agent_name: str, system_prompt: str, include_event_context: bool = True,
                 event_context_filename: Optional[str] = None):
        self.agent_name = agent_name
        self.system_prompt = system_prompt

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
            print(f"[{agent_name}] Loaded event context ({len(event_context)} chars) into system prompt.")

        prompt_parts.append(
            "You must output your analysis in strictly valid JSON matching this schema:\n"
            f"{AgentAnalysisReport.schema_json()}"
        )

        self.full_system_prompt = "\n\n".join(prompt_parts)
        self.conversation_history: List[Dict[str, str]] = [
            {"role": "system", "content": self.full_system_prompt}
        ]

        # --- AI Connection for Google Gemini API ---
        self.llm_client = AsyncOpenAI(
            api_key=os.getenv("GEMINI_API_KEY", "AIzaSyCKCbqW1aywKpElN35JVk_gsXg-FMqK668"), 
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/" 
        )
        self.model_name = os.getenv("LLM_MODEL", "gemini-2.5-flash") 
        
        self.MAX_PAYLOAD_CHARS = 30000 

    # ---------------------------------------------------------
    # SHARED FORENSIC UTILITIES
    # ---------------------------------------------------------

    def get_target_directory(self, base_staging_path: str, sub_path_parts: List[str]) -> Path:
        """Resolves target artifact directory or file from the main staging folder."""
        target_path = Path(base_staging_path).joinpath(*sub_path_parts)
        # Centralized folder creation
        if not target_path.exists():
            try:
                target_path.mkdir(parents=True, exist_ok=True)
                print(f"[CORE] Created missing directory: {target_path}")
            except Exception as e:
                print(f"[CORE] Error creating directory {target_path}: {e}")
        
        return target_path

    def _calculate_file_hashes(self, filepath: Path) -> Dict[str, str]:
        """Calculates MD5 and SHA256 hashes for suspicious files."""
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

    # Extensions we NEVER read the content of, no matter what -- these are
    # executables/binaries. We only ever list them (name, size, hash).
    _EXECUTABLE_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv"
    }

    # Known-binary forensic artifact extensions that are NOT executables but
    # are still not human-readable text (registry hives, event logs,
    # prefetch, sqlite/db, shortcut files, etc). Content is never read for
    # these either -- they get listed the same as raw inventory only.
    _BINARY_ARTIFACT_EXTENSIONS = {
        ".dat", ".hve", ".evtx", ".db", ".pf", ".lnk", ".zip", ".rar", ".7z",
        ".iso", ".img", ".bin"
    }

    def _looks_like_binary(self, filepath: Path, sniff_bytes: int = 4096) -> bool:
        """Safety-net sniff test: even if an extension isn't in our blocklist,
        don't read it as text if it actually contains binary data (null bytes /
        high ratio of non-printable bytes, or an MZ/executable header)."""
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(sniff_bytes)
            if not chunk:
                return False
            if chunk.startswith(b"MZ"):  # PE header
                return True
            if b"\x00" in chunk:
                return True
            nontext = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
            return (nontext / len(chunk)) > 0.30
        except Exception:
            return True  # if we can't safely sniff it, don't read it

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
        """Raw folder policy: ALWAYS list name/size/extension/hash. NEVER
        disassemble or otherwise reverse a binary. Only read the actual
        content when the file is a non-executable, non-binary, genuinely
        readable file (e.g. a .txt/.csv/.ini/.log dropped alongside the
        binaries) -- confirmed both by extension and by a raw-byte sniff."""
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

        # Hash everything under 50MB regardless of type -- hashing is not
        # "reading"/reversing, it's identification (for VT lookups etc).
        if stats.st_size < 50_000_000:
            entry.update(self._calculate_file_hashes(filepath))

        if is_executable or is_known_binary_artifact:
            entry["content_read"] = False
            entry["reason"] = "Executable/binary artifact -- listed only, not opened or reversed."
            return entry

        # Not flagged as binary by extension -- confirm with a byte sniff
        # before treating it as text, then read it.
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

    def parse_category_artifacts(
        self,
        staging_root: Path,
        category: str,
        metadata_row_filter: Optional[Dict[str, List[str]]] = None,
    ) -> str:
        """
        Reads one collector category folder, which always has the shape:
            <staging_root>/<category>/raw/       -> collected artifacts
            <staging_root>/<category>/metadata/   -> parser output (csv/txt)

        raw/       -> inventoried only (name, size, hash, extension). Content
                      is read ONLY for confirmed non-executable, non-binary,
                      genuinely text-readable files. Executables/binaries are
                      never opened, disassembled, or otherwise reversed.
        metadata/  -> read in full (already-parsed forensic tool output --
                      CSV/txt from PECmd, AmcacheParser, autorunsc, etc). This
                      is safe structured/text data, not a binary artifact.

        metadata_row_filter (optional): for CSV metadata files, keep only rows
        where any of `columns` contains any of `keywords` (case-insensitive).
        Example: {"columns": ["Category", "Entry Location"], "keywords": ["service"]}
        Used so multiple agents can share one collector category (e.g.
        SysinternalsAutoruns) but each only sees the rows relevant to it.
        """
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

        # --- raw/: list + selectively read only safe non-binary files ---
        if raw_dir.exists():
            for root, _, files in os.walk(raw_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    result["raw_inventory"].append(self._inventory_raw_file(fpath))
        else:
            result["raw_inventory_note"] = f"No raw/ folder present under {category_path}"

        # --- metadata/: already-parsed forensic output, always read as text/csv ---
        if meta_dir.exists():
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

                    result["metadata"].append(meta_entry)
        else:
            result["metadata_note"] = f"No metadata/ folder present under {category_path}"

        return self._truncate_payload(json.dumps(result))

    def parse_directory_to_json(self, target_path: Path, include_hashes: bool = False) -> str:
        """Extracts file metadata (and optionally hashes) from a directory."""
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
        """Parses CSV outputs from tools like AmcacheParser, PECmd, or RECmd."""
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
        """Parses Windows Scheduled Task XML files into structured JSON for the LLM."""
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
        """Prevents LLM Context Window overflow."""
        if len(payload) > self.MAX_PAYLOAD_CHARS:
            warning = f"\n\n[WARNING: Data truncated. Original length {len(payload)} chars, truncated to {self.MAX_PAYLOAD_CHARS} chars.]"
            return payload[:self.MAX_PAYLOAD_CHARS] + warning
        return payload

    # ---------------------------------------------------------
    # CORE AI & HITL LOGIC
    # ---------------------------------------------------------

    async def execute_llm_analysis(self, data_context: str) -> Dict:
        print(f"[{self.agent_name}] Running LLM inference...")
        try:
            response = await self.llm_client.chat.completions.create(
                model=self.model_name,
                messages=self.conversation_history,
                response_format={"type": "json_object"},
                temperature=0.1
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"[{self.agent_name}] LLM Error: {e}")
            return {"error": "Failed to generate analysis", "raw_exception": str(e)}

    async def send_to_dashboard_and_wait(self, response_payload: AgentResponse) -> HumanFeedback:
        print(f"\n{'='*50}\n[{self.agent_name}] ⏸️ PAUSED: Human Verification Required\n{'='*50}")
        print(f"--- AI ANALYSIS ---\n{json.dumps(response_payload.ai_analysis, indent=2)}\n-------------------")
        
        try:
            from web_hitl_bridge import bridge
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
            
            # Non-blocking async wait until web HITL decision is submitted
            await event.wait()
            
            record = bridge.pending_approvals.pop(self.agent_name, {})
            decision = record.get("decision", {"action": "APPROVE"})
            return HumanFeedback(action=decision.get("action", "APPROVE"), feedback=decision.get("feedback"))
        except Exception as e:
            print(f"[{self.agent_name}] Web HITL bridge fallback ({e}). Falling back to terminal prompt.")
            action = input(f"[{self.agent_name}] Human action (APPROVE/REVISE): ").strip().upper()
            if action == "REVISE":
                feedback = input(f"[{self.agent_name}] Enter instructions for the LLM: ")
                return HumanFeedback(action="REVISE", feedback=feedback)
            return HumanFeedback(action="APPROVE")

    async def run_with_hitl(self, parsed_tool_data: Any) -> AgentResponse:
        try:
            from web_hitl_bridge import bridge
            await bridge.wait_if_paused()
        except Exception:
            pass

        self.conversation_history.append({
            "role": "user", 
            "content": f"Analyze this newly extracted forensic data:\n{parsed_tool_data}"
        })

        while True:
            ai_conclusion_dict = await self.execute_llm_analysis(parsed_tool_data)
            current_state = AgentResponse(
                agent_name=self.agent_name,
                raw_data_parsed=parsed_tool_data,
                ai_analysis=ai_conclusion_dict
            )

            human_decision = await self.send_to_dashboard_and_wait(current_state)

            if human_decision.action == "APPROVE":
                print(f"[{self.agent_name}] ✅ APPROVED. Proceeding to next node.\n")
                current_state.status = "APPROVED"
                return current_state
            
            elif human_decision.action == "REVISE":
                print(f"[{self.agent_name}] 🔄 REVISION REQUESTED. Re-running analysis.\n")
                self.conversation_history.append({"role": "assistant", "content": json.dumps(ai_conclusion_dict)})
                self.conversation_history.append({
                    "role": "user", 
                    "content": f"Human Analyst Override: {human_decision.feedback}. Fix your analysis and return updated JSON."
                })