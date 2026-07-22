import os
import re
import sys
import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional

from core_agents import BaseHITLAgent, locate_staging_directory

# ===========================================================================
# 1. STRING EXTRACTION & REGEX CATEGORIZATION UTILITIES (TOOLS)
# ===========================================================================

def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII strings of at least min_len characters from raw bytes."""
    pattern = re.compile(b"[\x20-\x7e]{" + str(min_len).encode() + b",}")
    return [match.group(0).decode("ascii", errors="ignore") for match in pattern.finditer(data)]


def extract_unicode_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts UTF-16 (Unicode) strings of at least min_len characters from raw bytes."""
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
    Categorizes extracted string arrays into 5 key DFIR dimensions using regular expressions:
    - Network (IPs, URLs, Domains, User-Agents)
    - Obfuscated (Base64, Hex patterns)
    - Command Execution (PowerShell, CMD, LOLBins)
    - Paths & Registry (HKLM, AppData, Temp, File extensions)
    - Debug & Metadata (PDB paths, Compiler flags, Error messages)
    """
    regex_patterns = {
        "network": re.compile(
            r"(https?://[^\s\"']+|ftp://[^\s\"']+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|"
            r"[a-zA-Z0-9.-]+\.(?:com|org|net|io|ru|cn|xyz|top|info|biz|cc)|Mozilla/[0-9]|User-Agent)",
            re.IGNORECASE,
        ),
        "obfuscated": re.compile(
            r"([A-Za-z0-9+/]{40,}={0,2}|0x[0-9a-fA-F]{16,}|[a-fA-F0-9]{64})",
            re.IGNORECASE,
        ),
        "commands": re.compile(
            r"(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|"
            r"-enc|-EncodedCommand|-ExecutionPolicy|Bypass|-nop|-w hidden|invoke-expression|iex)",
            re.IGNORECASE,
        ),
        "paths_registry": re.compile(
            r"(HKLM\\|HKCU\\|Software\\Microsoft\\Windows\\CurrentVersion|System32\\|"
            r"%TEMP%|%APPDATA%|%USERPROFILE%|[a-zA-Z]:\\Windows\\[^\s\"']+|[a-zA-Z]:\\[^\s\"']+\.(exe|dll|bat|ps1|vbs|dat))",
            re.IGNORECASE,
        ),
        "debug_metadata": re.compile(
            r"(\.pdb\b|Visual Studio|GCC:|Clang|MSVC|Assertion failed|Debug\\|Release\\|"
            r"InternalName|OriginalFilename|VarFileInfo|VS_VERSION_INFO)",
            re.IGNORECASE,
        ),
    }

    categorized: Dict[str, List[str]] = {
        "network": [],
        "obfuscated": [],
        "commands": [],
        "paths_registry": [],
        "debug_metadata": [],
        "uncategorized": [],
    }

    seen = set()
    for s in strings_list:
        s_clean = s.strip()
        if not s_clean or s_clean in seen:
            continue
        seen.add(s_clean)

        matched = False
        for category, pattern in regex_patterns.items():
            if pattern.search(s_clean):
                categorized[category].append(s_clean)
                matched = True

        if not matched and len(s_clean) > 8:
            categorized["uncategorized"].append(s_clean)

    # Cap categories to avoid token overload
    for k in categorized:
        categorized[k] = categorized[k][:150]

    return categorized


# ===========================================================================
# 2. SPECIALIZED STRINGS FORENSIC SUB-AGENTS
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
                "Evaluate network-related strings: IPv4/IPv6 C2 addresses, suspicious domain names, "
                "HTTP/HTTPS URLs, custom User-Agent strings, API endpoint paths, and protocol signatures. "
                "Flag any hardcoded external IP addresses, dynamic DNS domains (e.g., duckdns, ngrok), "
                "non-standard user agents, or cleartext C2 beacon endpoints."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


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
                "Examine extracted binary strings for encoded payloads: long Base64 strings, "
                "hexadecimal byte arrays, XOR/RC4 key hints, obfuscated script blocks, and "
                "custom encoding indicators. Identify potential decoded intentions such as "
                "staged PE headers (TVqQA / MZ in base64), encrypted configuration blocks, or "
                "obfuscated PowerShell commands."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


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
                "Inspect extracted strings for command-line invocations: PowerShell flags (-enc, "
                "-ExecutionPolicy Bypass, -WindowStyle Hidden), cmd.exe calls, LOLBin utilities "
                "(certutil, bitsadmin, mshta, wscript, rundll32, regsvr32), and process spawn parameters. "
                "Flag any defense evasion flags, stealth execution switches, or automated script dropping logic."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


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
                "Examine registry paths (HKLM/HKCU Run keys, Services, UserInit), file drop locations "
                "(%TEMP%, %APPDATA%, ProgramData, System32), and environment variables. "
                "Flag paths associated with persistence mechanisms, privilege escalation, or malicious file staging."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


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
                "Analyze PDB (Program Database) paths (e.g. C:\\Users\\...\\Release\\malware.pdb), "
                "compiler/linker signatures, internal module names, export/import symbols, and error logs. "
                "Flag developer username remnants, project build directory structures, language indicators, "
                "or anti-debugging error strings useful for threat actor profiling."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


# ===========================================================================
# 3. MAIN COMPOSITE AGENT (FOR BACKWARDS COMPATIBILITY & MASTER ORCHESTRATION)
# ===========================================================================

class StringsAnalysisAgent(BaseHITLAgent):
    """
    File Analysis - Main Strings Analyzer Master Agent
    Developer Owner: [ N ]
    
    Orchestrates string extraction and deep LLM evaluation across ASCII/Unicode strings,
    C2 IPs/URLs, registry keys, Base64 payloads, execution strings, and debug metadata.
    """
    def __init__(self):
        super().__init__(
            agent_name="Strings_Analyzer",
            system_prompt=(
                "You are a Lead Reverse Engineer performing comprehensive string analysis on target binaries. "
                "Analyze ASCII and Unicode strings for Indicators of Compromise (IOCs): C2 IP addresses, domains, "
                "URL paths, hardcoded encryption keys, user-agent strings, suspicious registry locations, "
                "PowerShell/cmd.exe execution strings, base64/hex obfuscated data, and PDB build paths."
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
        """Processes File Analysis artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


# ===========================================================================
# 4. CLI ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = StringsAnalysisAgent()
    asyncio.run(agent.process_task(staging_root))
