"""
Reverse Engineering & String Analyzer -- Automation -> LLM Agent.

Automation step:
  1. Ghidra MCP headless auto-analysis (symbol resolution + per-function
     decompiled pseudocode + a complexity score) -- filtered down to the
     functions actually worth an LLM's attention (see _is_high_priority()).
  2. Safe string extraction (ASCII + UTF-16LE) and categorization, reused
     from this project's existing regex-based classifier.
  3. Automated decode of two obfuscation techniques that defeat a plain
     `strings` pass: single-byte XOR runs scanned directly out of the raw
     binary (find_xor_encoded_strings), and base64 blobs already isolated by
     the string categorizer (decode_base64_candidates).

LLM step: exactly one call per binary, over ONLY the filtered high-priority
functions' decompiled pseudocode plus the decoded string artifacts -- asked
to explain intent, identify crypto, reconstruct C2 config shape, and suggest
renames, with a strict system prompt (REVERSE_ENGINEERING_SYSTEM_PROMPT)
constraining it to the shared AgentAnalysisReport JSON schema every agent in
this codebase is already held to (see core/base_agent.py).
"""
import asyncio
import base64
import binascii
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base_agent import BaseHITLAgent
from core.models import DecodedStringArtifact, DecompiledFunctionFinding
from core.utils import locate_staging_directory
from . import mcp_client

AGENT_NAME = "Ghidra_Reverse_Engineering_Agent"

_ENTROPY_THRESHOLD = 2.5
_REPETITION_THRESHOLD = 0.6
_MIN_COMPLEXITY_FOR_LLM_REVIEW = 8
_MAX_FUNCTIONS_FOR_LLM_REVIEW = 15

_STOP_PHRASES = {
    "rem ", "remark", "note:", "network indicators", "obfuscated strings", "registry persistence",
    "file paths and artifacts", "debug metadata", "suspicious patterns", "system artifacts",
    "additional suspicious", "high entropy data", "command execution", "cryptocurrency addresses",
}

# Compiler-generated / CRT-init function names that show up in every binary
# regardless of what it actually does -- excluded from LLM review even if
# Ghidra reports high complexity for them, so the LLM budget goes to
# attacker-written logic, not boilerplate.
_STDLIB_NAME_PATTERNS = re.compile(
    r"^(_+|std::|__scrt_|__security_|__report_|_RTC_|__CxxFrameHandler|"
    r"_guard_|memcpy|memset|memmove|strlen|malloc|free)", re.IGNORECASE
)

REVERSE_ENGINEERING_SYSTEM_PROMPT = (
    "You are a Senior Reverse Engineer analyzing decompiled C pseudo-code produced by Ghidra headless "
    "auto-analysis. You are given a PRE-FILTERED list of high-complexity, non-library functions plus "
    "automatically-decoded string artifacts (XOR/base64) extracted from the same binary. For each function: "
    "explain its programmatic intent precisely; identify any cryptographic algorithm implemented or called "
    "(AES, RC4, ChaCha20, a custom XOR loop -- name it specifically, don't just say 'encryption'); if it "
    "appears to build/parse a C2 configuration structure, describe the structure's fields in order; and "
    "suggest a more descriptive replacement name for the function.\n\n"
    "Output STRUCTURED, DETERMINISTIC JSON only, matching the schema you were given at agent initialization. "
    "For every function you analyze, add exactly one entry to anomalies_found whose 'filepath' field is "
    "copied VERBATIM from that function's identifier line (e.g. 'sub_401000@0x401000'). Put your crypto "
    "algorithm identification, C2 structure reconstruction, and suggested rename inside 'justification' as "
    "clearly-labeled sentences (e.g. 'Crypto: RC4. C2 config: {host:cstr, port:u16}. Suggested rename: "
    "decrypt_c2_config'). Do not invent functions that were not in the input. If a function's logic is "
    "genuinely benign despite the complexity flag, still report it with severity 'Low' and say so -- do not "
    "omit it."
)


def _calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for c in set(s):
        p = s.count(c) / len(s)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_repetitive(s: str) -> bool:
    if len(s) < 8:
        return False
    for c in set(s):
        if c.isalnum() and s.count(c) / len(s) > _REPETITION_THRESHOLD:
            return True
    return False


def extract_ascii_strings(data: bytes, min_len: int = 8) -> List[str]:
    pattern = re.compile(b"[\x20-\x7e]{" + str(min_len).encode() + b",}")
    return [m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def extract_unicode_strings(data: bytes, min_len: int = 5) -> List[str]:
    pattern = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}")
    out = []
    for m in pattern.finditer(data):
        try:
            out.append(m.group(0).decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    return out


_OBFUSCATED_PATTERN = re.compile(r"([A-Za-z0-9+/]{40,}={0,2}|0x[0-9a-fA-F]{16,}|[a-fA-F0-9]{40,})")


def categorize_extracted_strings(strings_list: List[str]) -> Dict[str, List[str]]:
    """Cheap regex bucketing -- kept minimal here since the Static Triage
    module already owns the full IOC-pattern categorizer; this module only
    needs the 'obfuscated' bucket to feed into base64 decoding."""
    categorized: Dict[str, List[str]] = {"obfuscated": [], "other": []}
    seen = set()
    for s in strings_list:
        s_clean = s.strip()
        if not s_clean or s_clean in seen or s_clean.lower() in _STOP_PHRASES:
            continue
        seen.add(s_clean)
        if _calculate_entropy(s_clean) < _ENTROPY_THRESHOLD or _is_repetitive(s_clean):
            continue
        if _OBFUSCATED_PATTERN.search(s_clean):
            categorized["obfuscated"].append(s_clean)
        else:
            categorized["other"].append(s_clean)
    return categorized


_CONFIG_BLOB_KEYWORD = re.compile(r"\b(C2|CONFIG|HOST|PORT|MUTEX|CAMPAIGN|BUILDID)\b", re.IGNORECASE)
# '=' only, deliberately not ':' -- "http:" would otherwise match a
# key-value pair on the scheme separator of any plain URL.
_KEY_VALUE_PAIR = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+")


def _classify_decoded_text(text: str) -> Optional[str]:
    lowered = text.lower()
    if text.startswith("MZ"):
        return "embedded PE header"
    # Checked before the plain URL/IP checks below: a structured blob
    # (host=.../port=.../key=...) is more informative to report as
    # 'config-blob' than as merely 'IP address' just because one field
    # happens to be an IP.
    if _CONFIG_BLOB_KEYWORD.search(text) and len(_KEY_VALUE_PAIR.findall(text)) >= 1:
        return "config-blob"
    if "http://" in lowered or "https://" in lowered:
        return "URL"
    if re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text):
        return "IP address"
    if any(k in lowered for k in ("cmd.exe", "powershell", "\\windows\\", "/bin/")):
        return "command/path"
    return None


def _trim_padding_runs(text: str) -> tuple:
    """A raw byte-class regex match can bridge straight from a run of
    repeated padding bytes (0x00 * N, 0xFF * N, alignment filler...) into a
    real string, since XORing one repeated byte with a printable-range key
    is itself printable and looks like 'plain contiguous ASCII' to the
    regex. Strips leading/trailing runs of 4+ repeated identical characters
    before quality-checking the result. Returns (trimmed_text, chars_trimmed_
    from_start)."""
    start = 0
    end = len(text)
    while start < end - 3 and text[start] * 4 == text[start:start + 4]:
        run_char = text[start]
        while start < end and text[start] == run_char:
            start += 1
    while end > start + 3 and text[end - 4:end] == text[end - 1] * 4:
        run_char = text[end - 1]
        while end > start and text[end - 1] == run_char:
            end -= 1
    return text[start:end], start


def find_xor_encoded_strings(
    data: bytes, min_len: int = 6, max_candidates: int = 25, scan_window: int = 256_000
) -> List[DecodedStringArtifact]:
    """Scans raw bytes (bounded to the first `scan_window` bytes -- this is
    O(256 * window) in pure Python, so unbounded would be far too slow for a
    multi-MB binary) for byte runs that, under some single-byte XOR key,
    decode to a run of printable ASCII >= min_len containing at least one
    recognizable marker. This is the classic 'XOR string' obfuscation
    malware uses specifically to defeat a plain `strings` pass."""
    results: List[DecodedStringArtifact] = []
    scan_data = data[:scan_window]
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for key in range(1, 256):
        translated = bytes(b ^ key for b in scan_data)
        for match in pattern.finditer(translated):
            raw_text = match.group(0).decode("ascii")
            text, trimmed_from_start = _trim_padding_runs(raw_text)
            if len(text) < min_len:
                continue
            looks_like = _classify_decoded_text(text)
            if not looks_like:
                continue
            match_start = match.start() + trimmed_from_start
            match_end = match_start + len(text)
            results.append(DecodedStringArtifact(
                encoded=scan_data[match_start:match_end].hex(),
                decoded=text,
                encoding=f"single-byte-xor:0x{key:02x}",
                offset=hex(match_start),
                looks_like=looks_like,
            ))
            if len(results) >= max_candidates:
                return results
    return results


def decode_base64_candidates(candidates: List[str], max_results: int = 25) -> List[DecodedStringArtifact]:
    """Attempts base64 decode on every string the categorizer already
    isolated as base64-shaped; keeps only decodes that produce printable
    text or a recognizable embedded-file magic header."""
    results = []
    for s in candidates[:200]:
        try:
            decoded_bytes = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            continue
        looks_like = None
        if decoded_bytes.startswith(b"MZ"):
            text, looks_like = "<binary PE payload>", "embedded PE header"
        else:
            try:
                text = decoded_bytes.decode("utf-8")
                if not text.isprintable():
                    continue
            except UnicodeDecodeError:
                continue
            looks_like = _classify_decoded_text(text)
            if not looks_like:
                continue
        results.append(DecodedStringArtifact(encoded=s, decoded=text, encoding="base64", looks_like=looks_like))
        if len(results) >= max_results:
            break
    return results


def _is_high_priority(func: Dict[str, Any]) -> bool:
    name = str(func.get("name", ""))
    complexity = int(func.get("complexity") or func.get("cyclomatic_complexity") or 0)
    return complexity >= _MIN_COMPLEXITY_FOR_LLM_REVIEW and not _STDLIB_NAME_PATTERNS.match(name)


def _function_key(name: str, address: str) -> str:
    return f"{name}@{address}"


async def _run_ghidra_headless(fpath: Path) -> Dict[str, Any]:
    return await mcp_client.call_tool(mcp_client.GHIDRA_MCP, "analyze_binary", {"path": str(fpath)})


def _collect_binaries(staging_root: Path, max_binaries: int = 15) -> List[Path]:
    binary_extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv", ".elf", ".so", ".bin"}
    max_file_size = 50_000_000
    found = []
    for category_dir in staging_root.iterdir():
        if not category_dir.is_dir():
            continue
        raw_dir = category_dir / "raw"
        if not raw_dir.exists():
            continue
        for root, _, files in os.walk(raw_dir):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in binary_extensions:
                    continue
                try:
                    if fpath.stat().st_size > max_file_size:
                        continue
                except Exception:
                    continue
                found.append(fpath)
                if len(found) >= max_binaries:
                    return found
    return found


class ReverseEngineeringAndStringAnalyzerAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name=AGENT_NAME,
            system_prompt=REVERSE_ENGINEERING_SYSTEM_PROMPT,
        )

    async def process_task(self, staging_root: Path):
        binaries = _collect_binaries(staging_root)
        if not binaries:
            parsed_json_data = json.dumps({"error": "No PE/ELF binaries found to reverse engineer."})
            return await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        per_binary_payloads = []
        function_index: Dict[str, Dict[str, Any]] = {}

        for fpath in binaries:
            ghidra_result = await _run_ghidra_headless(fpath)
            functions = ghidra_result.get("functions", []) if isinstance(ghidra_result, dict) else []
            high_priority = [f for f in functions if _is_high_priority(f)][:_MAX_FUNCTIONS_FOR_LLM_REVIEW]

            try:
                with open(fpath, "rb") as f:
                    data = f.read()
            except Exception:
                data = b""

            ascii_strings = extract_ascii_strings(data)
            unicode_strings = extract_unicode_strings(data)
            categorized = categorize_extracted_strings(ascii_strings + unicode_strings)
            decoded_strings = (
                find_xor_encoded_strings(data)
                + decode_base64_candidates(categorized.get("obfuscated", []))
            )

            review_functions = []
            for func in high_priority:
                key = _function_key(str(func.get("name", "?")), str(func.get("address", "?")))
                function_index[key] = {"filepath": str(fpath), "function": func}
                review_functions.append({
                    "identifier": key,
                    "complexity": func.get("complexity") or func.get("cyclomatic_complexity"),
                    "decompiled_pseudocode": func.get("decompiled") or func.get("pseudocode") or "",
                })

            per_binary_payloads.append({
                "filepath": str(fpath.relative_to(staging_root)),
                "ghidra_project": ghidra_result.get("project") if isinstance(ghidra_result, dict) else None,
                "functions_total": len(functions),
                "functions_sent_for_review": len(review_functions),
                "review_functions": review_functions,
                "decoded_strings": [d.dict() for d in decoded_strings],
            })

        parsed_json_data = self._truncate_payload(json.dumps({
            "staging_root": str(staging_root),
            "binaries": per_binary_payloads,
        }, default=str))

        response = await self.run_with_hitl(parsed_tool_data=parsed_json_data)

        if response.status == "APPROVED":
            findings: List[DecompiledFunctionFinding] = []
            for anomaly in response.ai_analysis.get("anomalies_found", []):
                if not isinstance(anomaly, dict):
                    continue
                key = anomaly.get("filepath", "")
                indexed = function_index.get(key)
                if not indexed:
                    continue
                func = indexed["function"]
                justification = anomaly.get("justification", "")
                crypto_match = re.search(r"\b(AES|RC4|ChaCha20|DES|Blowfish|Custom XOR)\b", justification, re.IGNORECASE)
                rename_match = re.search(r"[Ss]uggested rename:\s*([A-Za-z0-9_]+)", justification)
                findings.append(DecompiledFunctionFinding(
                    function_name=str(func.get("name", "?")),
                    address=str(func.get("address", "?")),
                    cyclomatic_complexity=int(func.get("complexity") or func.get("cyclomatic_complexity") or 0),
                    is_high_priority=True,
                    priority_reason="Complexity >= threshold and not a recognized stdlib/CRT name",
                    intent_summary=justification,
                    crypto_algorithm_identified=crypto_match.group(1) if crypto_match else None,
                    suggested_rename=rename_match.group(1) if rename_match else None,
                    anti_analysis_technique=anomaly.get("anomaly_type") if "anti" in anomaly.get("anomaly_type", "").lower() else None,
                ))
            response.ai_analysis["_function_findings"] = [f.dict() for f in findings]
            await self._submit_renames_to_ghidra(findings, function_index)

        return response

    async def _submit_renames_to_ghidra(
        self, findings: List[DecompiledFunctionFinding], function_index: Dict[str, Dict[str, Any]]
    ) -> None:
        """Pushes each LLM-suggested rename back into the live Ghidra project
        via the same 'rename_function' MCP tool contract analyze_binary's
        server is expected to expose -- only runs after HITL approval,
        mirroring Memory Analysis's approval-gated malfind handoff. Requires
        an actual Ghidra MCP server with that tool; degrades to a logged WARN
        (never raises) if it doesn't, the same contract every other
        mcp_client.call_tool() caller in this codebase follows."""
        from bridge.hitl_bridge import bridge

        for f in findings:
            if not f.suggested_rename:
                continue
            key = _function_key(f.function_name, f.address)
            indexed = function_index.get(key)
            if not indexed:
                continue
            result = await mcp_client.call_tool(mcp_client.GHIDRA_MCP, "rename_function", {
                "path": indexed["filepath"],
                "address": f.address,
                "old_name": f.function_name,
                "new_name": f.suggested_rename,
            })
            if result:
                bridge.log_event(
                    AGENT_NAME,
                    f"Renamed {f.function_name}@{f.address} -> {f.suggested_rename} in the live Ghidra project.",
                    level="INFO",
                )
            else:
                bridge.log_event(
                    AGENT_NAME,
                    f"Rename suggestion {f.function_name}@{f.address} -> {f.suggested_rename} was NOT applied "
                    f"(no reachable Ghidra MCP 'rename_function' tool) -- apply manually in Ghidra if needed.",
                    level="WARN",
                )


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = ReverseEngineeringAndStringAnalyzerAgent()
    asyncio.run(agent.process_task(staging_root))
