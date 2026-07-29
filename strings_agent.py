import os
import re
import math
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional

from core_agents import BaseHITLAgent

# ---------------------------------------------------------------------------
# NOTE ON STRINGS ANALYSIS WORKFLOW
# ---------------------------------------------------------------------------
# collector_agent.py stages evidence as:
#     <staging_root>/<Category>/raw/       -> collected files
#     <staging_root>/<Category>/metadata/  -> parser output (csv/txt)
#
# The StringsAnalysisAgent scans all <Category>/raw/ directories for executable
# binaries (.exe, .dll, .sys, .scr, .com, .msi, .cpl, .ocx, .drv). For each
# binary found, it performs safe string extraction:
#   - Printable ASCII strings (minimum length 8)
#   - UTF-16LE (Unicode) strings (minimum length 5)
#
# Extracted strings are deduplicated and categorized into 6 DFIR dimensions:
#   network, obfuscated, commands, paths_registry, debug_metadata, api_calls
#
# The final structured JSON payload is fed to the LLM for anomaly detection.
# String extraction is a safe forensic technique -- it does NOT involve
# disassembly, decompilation, or execution of the binary.
# ---------------------------------------------------------------------------


# ===========================================================================
# 0. QUALITY FILTERS (reduce noise before categorization)
# ===========================================================================

_ENTROPY_THRESHOLD = 2.5
_REPETITION_THRESHOLD = 0.6

_STOP_PHRASES = {
    "rem ", "remark", "note:",
    "network indicators", "obfuscated strings", "registry persistence",
    "file paths and artifacts", "debug metadata", "suspicious patterns",
    "system artifacts", "additional suspicious", "high entropy data",
    "command execution", "cryptocurrency addresses",
}


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
    for plen in range(2, min(6, len(s) // 2 + 1)):
        if len(s) % plen == 0:
            pattern = s[:plen]
            if pattern.isalnum() and pattern * (len(s) // plen) == s:
                return True
    return False


def _is_stop_string(s: str) -> bool:
    cleaned = s.strip().lower()
    for phrase in _STOP_PHRASES:
        if cleaned.startswith(phrase) or cleaned == phrase:
            return True
    return False


def _strip_echo(s: str) -> str:
    if s.lower().startswith("echo "):
        return s[5:]
    return s


def _looks_like_obfuscated(s: str) -> bool:
    if len(s) < 20:
        return False
    has_plus = '+' in s
    has_slash = '/' in s
    has_padding = s.endswith('=')
    has_hex_prefix = s.startswith('0x') or s.startswith('0X')
    if s.replace('+', '').replace('/', '').replace('=', '').replace('\\', '').isalpha():
        return has_hex_prefix
    if has_plus or has_slash or has_padding or has_hex_prefix:
        return True
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if len(s) >= 40 and all(c in base64_chars for c in s):
        has_mixed = any(c.islower() for c in s) and any(c.isupper() for c in s)
        has_digits = any(c.isdigit() for c in s)
        return has_mixed or has_digits
    return False


def _is_escape_noise(s: str) -> bool:
    if len(s) < 10:
        return False
    backslash_count = s.count('\\')
    if backslash_count > 0 and backslash_count / len(s) > 0.20:
        return True
    return False


# ===========================================================================
# 1. STRING EXTRACTION & REGEX CATEGORIZATION UTILITIES (TOOLS)
# ===========================================================================

def extract_ascii_strings(data: bytes, min_len: int = 8) -> List[str]:
    """Extracts printable ASCII strings of at least min_len characters from raw bytes."""
    pattern = re.compile(b"[\x20-\x7e]{" + str(min_len).encode() + b",}")
    return [match.group(0).decode("ascii", errors="ignore") for match in pattern.finditer(data)]


def extract_unicode_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extracts UTF-16LE (Unicode) strings of at least min_len characters from raw bytes."""
    pattern = re.compile(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}")
    results = []
    for match in pattern.finditer(data):
        try:
            results.append(match.group(0).decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    return results


def categorize_extracted_strings(strings_list: List[str]) -> Dict[str, List[str]]:
    """
    Categorizes extracted string arrays into 6 DFIR dimensions using regular expressions:
    - Network (IPs, URLs, Domains, User-Agents)
    - Obfuscated (Base64, Hex patterns)
    - Command Execution (PowerShell, CMD, LOLBins)
    - Paths & Registry (HKLM, AppData, Temp, File extensions)
    - Debug & Metadata (PDB paths, Compiler flags, Error messages)
    - API Calls (Win32 API, process injection, reverse engineering artifacts)
    """
    regex_patterns = {
        "network": re.compile(
            r"(https?://[^\s\"']+|ftp://[^\s\"']+|"
            r"https?(?![a-zA-Z]*://)[a-zA-Z0-9.-]+\.(?:[a-zA-Z]{2,})?(?:/[^\s\"']*)?|"
            r"(?<!\d)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\d{2,5})?(?!\d)|"
            r"[a-zA-Z0-9.-]+\.(?:com|org|net|io|ru|cn|xyz|top|info|biz|cc|"
            r"tk|ml|cf|ga|gq|click|download|review|pw|work|"
            r"men|mom|cyou|sbs|gdn|bond|rest|science|party|date|"
            r"racing|accountant|loan|faith|bid|win|trade|webcam)|"
            r"Mozilla/[0-9]|User-Agent)",
            re.IGNORECASE,
        ),
        "obfuscated": re.compile(
            r"([A-Za-z0-9+/]{40,}={0,2}|0x[0-9a-fA-F]{16,}|[a-fA-F0-9]{40,})",
            re.IGNORECASE,
        ),
        "commands": re.compile(
            r"(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|"
            r"-enc|-EncodedCommand|-ExecutionPolicy|Bypass|-nop|-w hidden|invoke-expression|iex|"
            r"psexec|paexec|schtasks|sc\s+create|net\s+use|wmic)",
            re.IGNORECASE,
        ),
        "paths_registry": re.compile(
            r"(HKLM\\|HKCU\\|HKCR\\|HKU\\|HKLM\S+|HKCU\S+|HKCR\S+|HKU\S+|"
            r"Software\\Microsoft\\Windows\\CurrentVersion|System32\\|"
            r"%TEMP%|%APPDATA%|%USERPROFILE%|"
            r"Reg\s+Add|REG_EXPAND_SZ|"
            r"[a-zA-Z]:\\Windows\\[^\s\"']+|[a-zA-Z]:\\[^\s\"']+\.(?:exe|dll|bat|ps1|vbs|dat))",
            re.IGNORECASE,
        ),
        "debug_metadata": re.compile(
            r"(\.pdb\b|Visual Studio|GCC:|Clang|MSVC|Assertion failed|Debug\\|Release\\|"
            r"InternalName|OriginalFilename|VarFileInfo|VS_VERSION_INFO|"
            r"CompanyName|LegalCopyright|FileDescription|ProductName)",
            re.IGNORECASE,
        ),
        "api_calls": re.compile(
            r"(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|"
            r"LoadLibrary(?:A|W|Ex)?|GetProcAddress|IsDebuggerPresent|"
            r"CheckRemoteDebuggerPresent|NtQueryInformationProcess|GetTickCount|"
            r"Sleep\s*\(\s*\d+|CreateProcess(?:A|W)?|"
            r"OpenProcess|VirtualProtectEx|SetWindowsHookEx|"
            r"EnumProcessModules|CreateToolhelp32Snapshot|Process32First(?:Next)?|"
            r"mimikatz|sekurlsa::logonpasswords|lsadump::sam|privilege::debug|token::elevate|"
            r"cobalt\s*strike|metasploit|reverse_tcp|bind_shell)",
            re.IGNORECASE,
        ),
    }

    categorized: Dict[str, List[str]] = {
        "network": [],
        "obfuscated": [],
        "commands": [],
        "paths_registry": [],
        "debug_metadata": [],
        "api_calls": [],
        "uncategorized": [],
    }

    seen = set()
    for s in strings_list:
        s_clean = s.strip()
        if not s_clean:
            continue

        s_match = _strip_echo(s_clean)
        if not s_match or s_match in seen:
            continue
        seen.add(s_match)

        if _calculate_entropy(s_match) < _ENTROPY_THRESHOLD:
            continue
        if _is_repetitive(s_match):
            continue
        if _is_stop_string(s_match):
            continue
        if _is_escape_noise(s_match):
            continue

        matched = False
        for category, pattern in regex_patterns.items():
            if pattern.search(s_match):
                if category == "obfuscated" and not _looks_like_obfuscated(s_match):
                    continue
                categorized[category].append(s_match)
                matched = True

        if not matched and len(s_match) > 8:
            categorized["uncategorized"].append(s_match)

    for k in categorized:
        categorized[k] = categorized[k][:150]

    return categorized


# ===========================================================================
# 2. SHARED STRING EXTRACTION HELPER (used by all agents below)
# ===========================================================================

def _build_strings_payload(
    staging_root: Path,
    hash_fn,
    truncate_fn,
    category_filter: Optional[str] = None,
) -> str:
    """
    Scans the staging directory for executable binaries, extracts ASCII/Unicode
    strings, categorizes them, and returns a JSON string payload.

    Args:
        staging_root: Path to the investigation staging directory.
        hash_fn: Reference to _calculate_file_hashes method.
        truncate_fn: Reference to _truncate_payload method.
        category_filter: If given (e.g. 'network'), only that category is included
                         in the per-binary output. If None, all categories are included.
    """
    binary_extensions = {
        ".exe", ".dll", ".sys", ".scr", ".com", ".msi",
        ".cpl", ".ocx", ".drv"
    }
    max_file_size = 50_000_000  # 50 MB safety cap
    max_binaries = 15
    max_strings_per_binary = 300

    findings = []
    total_binaries_scanned = 0
    total_binaries_skipped = 0

    for category_dir in staging_root.iterdir():
        if not category_dir.is_dir():
            continue

        raw_dir = category_dir / "raw"
        if not raw_dir.exists():
            continue

        for root, _, files in os.walk(raw_dir):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext not in binary_extensions:
                    continue

                # Enforce max binaries cap
                if total_binaries_scanned >= max_binaries:
                    break

                try:
                    stats = fpath.stat()
                except Exception:
                    continue

                # Skip oversized files
                if stats.st_size > max_file_size:
                    total_binaries_skipped += 1
                    findings.append({
                        "filepath": str(fpath.relative_to(staging_root)),
                        "filename": fname,
                        "size_bytes": stats.st_size,
                        "skipped": True,
                        "skip_reason": "File exceeds 50MB size limit for string extraction",
                    })
                    continue

                # Extract strings
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                except Exception:
                    continue

                total_binaries_scanned += 1
                ascii_strings = extract_ascii_strings(data, min_len=8)
                unicode_strings = extract_unicode_strings(data, min_len=5)
                all_strings = ascii_strings + unicode_strings

                # Deduplicate and cap per binary
                seen = set()
                unique_strings = []
                for s in all_strings:
                    if s not in seen and len(s) >= 5:
                        seen.add(s)
                        unique_strings.append(s)
                unique_strings = unique_strings[:max_strings_per_binary]

                categorized = categorize_extracted_strings(unique_strings)

                # Apply category filter if requested
                if category_filter and category_filter in categorized:
                    filtered_categorized = {category_filter: categorized[category_filter]}
                else:
                    filtered_categorized = categorized

                # Calculate hashes for correlation with other agents
                hashes = hash_fn(fpath)

                findings.append({
                    "filepath": str(fpath.relative_to(staging_root)),
                    "filename": fname,
                    "size_bytes": stats.st_size,
                    "extension": ext,
                    "hashes": hashes,
                    "strings_extracted": {
                        "total_unique": len(unique_strings),
                        "ascii_count": len(ascii_strings),
                        "unicode_count": len(unicode_strings),
                    },
                    "categorized_strings": filtered_categorized,
                    "skipped": False,
                })

            if total_binaries_scanned >= max_binaries:
                break

    payload = {
        "analysis_type": "strings_analysis",
        "staging_root": str(staging_root),
        "total_binaries_scanned": total_binaries_scanned,
        "total_binaries_skipped": total_binaries_skipped,
        "note": (
            "String extraction is a safe forensic technique. No binary was disassembled, "
            "decompiled, or executed. Only printable ASCII and UTF-16LE strings were extracted."
        ),
        "findings": findings,
    }

    return truncate_fn(json.dumps(payload, indent=2))


# ===========================================================================
# 3. SPECIALIZED STRINGS FORENSIC SUB-AGENTS
# ===========================================================================

class NetworkStringsAgent(BaseHITLAgent):
    """
    Strings Analysis - Network & C2 Indicators Sub-Agent
    Analyzes C2 IP addresses, domains, URLs, HTTP headers, User-Agents, and communication strings.
    """
    def __init__(self):
        super().__init__(
            agent_name="Network_Strings_Analyzer",
            system_prompt=(
                "You are a DFIR Network Forensics Expert analyzing extracted binary string artifacts. "
                "You are given ONLY network-related strings from target binaries: IPv4/IPv6 addresses, "
                "suspicious domain names, HTTP/HTTPS URLs, custom User-Agent strings, API endpoint paths, "
                "and protocol signatures. "
                "Flag any hardcoded external IP addresses, dynamic DNS domains (e.g., duckdns, ngrok, no-ip), "
                "non-standard user agents, or cleartext C2 beacon endpoints. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )

    async def process_task(self, staging_root: Path):
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
            category_filter="network",
        )
        return await self.run_with_hitl(parsed_tool_data=payload)


class ObfuscatedPayloadAgent(BaseHITLAgent):
    """
    Strings Analysis - Obfuscated & Encoded Payloads Sub-Agent
    Hunts for Base64 payloads, XOR/RC4 key hints, hex-encoded shellcode, and high-entropy text blocks.
    """
    def __init__(self):
        super().__init__(
            agent_name="Obfuscated_Payload_Analyzer",
            system_prompt=(
                "You are a Reverse Engineer specializing in malware obfuscation. "
                "You are given ONLY obfuscated/encoded strings extracted from target binaries: "
                "long Base64 strings, hexadecimal byte arrays, XOR/RC4 key hints, obfuscated script blocks, "
                "and custom encoding indicators. "
                "Identify potential decoded intentions such as staged PE headers (TVqQA / MZ in base64), "
                "encrypted configuration blocks, or obfuscated PowerShell commands. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )

    async def process_task(self, staging_root: Path):
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
            category_filter="obfuscated",
        )
        return await self.run_with_hitl(parsed_tool_data=payload)


class CommandExecutionAgent(BaseHITLAgent):
    """
    Strings Analysis - Command & Process Execution Sub-Agent
    Focuses on CLI flags, PowerShell arguments, LOLBins, and process invocation patterns.
    """
    def __init__(self):
        super().__init__(
            agent_name="Command_Execution_Analyzer",
            system_prompt=(
                "You are an Incident Responder analyzing process execution strings. "
                "You are given ONLY command-line and execution-related strings from target binaries: "
                "PowerShell flags (-enc, -ExecutionPolicy Bypass, -WindowStyle Hidden), cmd.exe calls, "
                "LOLBins (certutil, bitsadmin, mshta, wscript, rundll32, regsvr32), and process spawn parameters. "
                "Flag any defense evasion flags, stealth execution switches, or automated script dropping logic. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )

    async def process_task(self, staging_root: Path):
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
            category_filter="commands",
        )
        return await self.run_with_hitl(parsed_tool_data=payload)


class PathAndRegistryStringsAgent(BaseHITLAgent):
    """
    Strings Analysis - Filesystem & Registry Paths Sub-Agent
    Evaluates hardcoded file paths, drop directories, registry hive keys, and system environment variables.
    """
    def __init__(self):
        super().__init__(
            agent_name="Path_Registry_Strings_Analyzer",
            system_prompt=(
                "You are a Windows Forensics Specialist analyzing filesystem and registry paths embedded in binaries. "
                "You are given ONLY path and registry-related strings from target binaries: "
                "registry paths (HKLM/HKCU Run keys, Services, UserInit), file drop locations "
                "(%TEMP%, %APPDATA%, ProgramData, System32), and environment variables. "
                "Flag paths associated with persistence mechanisms, privilege escalation, or malicious file staging. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )

    async def process_task(self, staging_root: Path):
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
            category_filter="paths_registry",
        )
        return await self.run_with_hitl(parsed_tool_data=payload)


class DebugAndMetadataStringsAgent(BaseHITLAgent):
    """
    Strings Analysis - Debug & Metadata Artifacts Sub-Agent
    Analyzes PDB debug paths, compiler signatures, internal symbol tables, and diagnostic strings.
    """
    def __init__(self):
        super().__init__(
            agent_name="Debug_Metadata_Analyzer",
            system_prompt=(
                "You are a Binary Attribution Expert inspecting compilation and debug metadata. "
                "You are given ONLY debug and metadata strings from target binaries: "
                "PDB (Program Database) paths (e.g. C:\\Users\\...\\Release\\malware.pdb), "
                "compiler/linker signatures, internal module names, export/import symbols, and error logs. "
                "Flag developer username remnants, project build directory structures, language indicators, "
                "or anti-debugging error strings useful for threat actor profiling. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )

    async def process_task(self, staging_root: Path):
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
            category_filter="debug_metadata",
        )
        return await self.run_with_hitl(parsed_tool_data=payload)


# ===========================================================================
# 4. MAIN COMPOSITE STRINGS ANALYSIS AGENT
# ===========================================================================

class StringsAnalysisAgent(BaseHITLAgent):
    """
    File Analysis - Main Strings Analyzer Agent
    Developer Owner: [ N ]

    Orchestrates safe string extraction and deep LLM evaluation across ASCII/Unicode strings
    found in executable binaries staged by the collector. Extracts and categorizes strings into
    network IOCs, obfuscated payloads, command execution artifacts, filesystem/registry paths,
    and debug metadata for comprehensive binary attribution and threat hunting.
    """
    def __init__(self):
        super().__init__(
            agent_name="Strings_Analyzer",
            system_prompt=(
                "You are a Lead Reverse Engineer performing comprehensive string analysis on target binaries. "
                "You are given structured output containing ASCII and Unicode strings extracted safely from "
                "executable binaries (.exe, .dll, .sys, etc.) found in the investigation staging directory. "
                "Each binary entry includes its filepath, size, hashes, and categorized strings. "
                "Analyze all categories for Indicators of Compromise (IOCs): "
                "C2 IP addresses, domains, URL paths, hardcoded encryption keys, user-agent strings, "
                "suspicious registry locations, PowerShell/cmd.exe execution strings, base64/hex obfuscated data, "
                "and PDB build paths. "
                "You must output your analysis in strictly valid JSON matching the AgentAnalysisReport schema."
            )
        )
        # Internal swarm of sub-agents available for modular execution
        self.sub_agents = [
            NetworkStringsAgent(),
            ObfuscatedPayloadAgent(),
            CommandExecutionAgent(),
            PathAndRegistryStringsAgent(),
            DebugAndMetadataStringsAgent(),
        ]

    async def process_task(self, staging_root: Path):
        """
        Scans the staging directory for binaries, extracts and categorizes strings,
        and runs the full LLM + HITL analysis pipeline.
        """
        payload = _build_strings_payload(
            staging_root,
            self._calculate_file_hashes,
            self._truncate_payload,
        )
        return await self.run_with_hitl(parsed_tool_data=payload)
