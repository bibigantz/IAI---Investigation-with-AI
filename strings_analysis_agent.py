import os
import re
import sys
import json
import asyncio
import math
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter

from core_agents import BaseHITLAgent, locate_staging_directory

# ===========================================================================
# 1. STRING EXTRACTION & REGEX CATEGORIZATION UTILITIES (TOOLS)
# ===========================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data to detect packing/encryption."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


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


def try_decode_base64(s: str) -> Optional[str]:
    """Attempt to decode a Base64 string, return decoded text if valid."""
    try:
        # Add padding if missing
        padded = s + '=' * (-len(s) % 4)
        decoded = base64.b64decode(padded)
        # Check if result is printable ASCII
        if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
            return decoded.decode('ascii', errors='ignore')
    except Exception:
        pass
    return None


def categorize_extracted_strings(strings_list: List[str]) -> Dict[str, List[str]]:
    """
    Categorizes extracted string arrays into key DFIR dimensions using regular expressions:
    - Network (IPs, URLs, Domains, User-Agents)
    - Obfuscated (Base64, Hex patterns)
    - Command Execution (PowerShell, CMD, LOLBins)
    - Paths & Registry (HKLM, AppData, Temp, File extensions)
    - Debug & Metadata (PDB paths, Compiler flags, Error messages)
    - Cryptocurrency (BTC, ETH addresses)
    - System Artifacts (Mutex names, WinAPI calls, Event IDs)
    """
    regex_patterns = {
        "network": re.compile(
            r"(https?://[^\s\"']+|ftp://[^\s\"']+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|"
            r"[a-zA-Z0-9.-]+\.(?:com|org|net|io|ru|cn|xyz|top|info|biz|cc|tk|ml|ga|cf|pw)|Mozilla/[0-9]|User-Agent:)",
            re.IGNORECASE,
        ),
        "obfuscated": re.compile(
            r"([A-Za-z0-9+/]{40,}={0,2}|0x[0-9a-fA-F]{16,}|[a-fA-F0-9]{64}|\b[A-Z][a-z]+[A-Z][a-zA-Z]+)",
            re.IGNORECASE,
        ),
        "commands": re.compile(
            r"(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|wmic|psexec|paexec|"
            r"-enc|-EncodedCommand|-ExecutionPolicy|Bypass|-nop|-w hidden|invoke-expression|iex|downloadstring|"
            r"frombase64string|webclient|httprequest|wininet|internetopen)",
            re.IGNORECASE,
        ),
        "paths_registry": re.compile(
            r"(HKLM\\|HKCU\\|Software\\Microsoft\\Windows\\CurrentVersion|System32\\|"
            r"%TEMP%|%APPDATA%|%USERPROFILE%|%WINDIR%|[a-zA-Z]:\\Windows\\[^\s\"']+|[a-zA-Z]:\\[^\s\"']+\.(exe|dll|bat|ps1|vbs|dat|tmp))",
            re.IGNORECASE,
        ),
        "debug_metadata": re.compile(
            r"(\.pdb\b|Visual Studio|GCC:|Clang|MSVC|Assertion failed|Debug\\|Release\\|"
            r"InternalName|OriginalFilename|VarFileInfo|VS_VERSION_INFO|CompanyName|LegalCopyright|FileDescription)",
            re.IGNORECASE,
        ),
        "cryptocurrency": re.compile(
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|0x[a-fA-F0-9]{40}\b",
            re.IGNORECASE,
        ),
        "system_artifacts": re.compile(
            r"(Global\\[a-zA-Z0-9_-]+|Local\\[a-zA-Z0-9_-]+|CreateProcess|VirtualAlloc|WriteProcessMemory|"
            r"CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookEx|GetAsyncKeyState|RegSetValue|OpenProcess|"
            r"EventID\s*\d+|TaskScheduler|ServiceControlManager)",
            re.IGNORECASE,
        ),
    }

    categorized: Dict[str, List[str]] = {
        "network": [],
        "obfuscated": [],
        "commands": [],
        "paths_registry": [],
        "debug_metadata": [],
        "cryptocurrency": [],
        "system_artifacts": [],
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
                break  # Only categorize once

        if not matched and len(s_clean) > 8:
            categorized["uncategorized"].append(s_clean)

    # Cap categories to avoid token overload
    for k in categorized:
        categorized[k] = categorized[k][:200]

    return categorized


def extract_strings_from_file(filepath: Path, min_len: int = 4) -> Dict[str, Any]:
    """
    Extract ASCII and Unicode strings from a binary file.
    Returns dict with strings, entropy, and file metadata.
    """
    result = {
        "filepath": str(filepath),
        "filename": filepath.name,
        "size_bytes": 0,
        "entropy": 0.0,
        "ascii_strings": [],
        "unicode_strings": [],
        "all_strings": [],
        "error": None
    }
    
    try:
        file_size = filepath.stat().st_size
        result["size_bytes"] = file_size
        
        # Skip very large files (>50MB) for string extraction
        if file_size > 50_000_000:
            result["error"] = "File too large for string extraction (>50MB)"
            return result
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Calculate entropy
        result["entropy"] = round(calculate_entropy(data), 3)
        
        # Extract strings
        ascii_strs = extract_ascii_strings(data, min_len)
        unicode_strs = extract_unicode_strings(data, min_len)
        
        result["ascii_strings"] = ascii_strs[:500]  # Limit per file
        result["unicode_strings"] = unicode_strs[:500]
        result["all_strings"] = list(set(ascii_strs + unicode_strs))[:800]
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def extract_strings_from_directory(dir_path: Path, min_len: int = 4, max_files: int = 50) -> List[Dict[str, Any]]:
    """
    Extract strings from all binary files in a directory.
    Prioritizes executable files and limits total files processed.
    """
    results = []
    executable_extensions = {'.exe', '.dll', '.sys', '.scr', '.com', '.msi', '.cpl', '.ocx'}
    other_extensions = {'.bin', '.dat', '.drv', '.efi'}
    
    # Collect candidate files
    candidates = []
    for root, _, files in os.walk(dir_path):
        for fname in files:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext in executable_extensions or ext in other_extensions:
                candidates.append((fpath, 0))  # Priority 0 for executables
            elif ext == '' or ext in {'.tmp', '.temp'}:
                candidates.append((fpath, 1))  # Priority 1 for extensionless/temp
    
    # Sort by priority then by size (smaller first for faster processing)
    candidates.sort(key=lambda x: (x[1], x[0].stat().st_size if x[0].exists() else 0))
    
    # Process limited number of files
    for fpath, _ in candidates[:max_files]:
        if fpath.exists() and fpath.is_file():
            result = extract_strings_from_file(fpath, min_len)
            results.append(result)
    
    return results


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
        # Extract strings from binaries in multiple relevant categories
        all_strings = []
        entropy_findings = []
        
        for category in ["TempFolder", "Downloads", "StartupFolders"]:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=20)
                for fr in file_results:
                    all_strings.extend(fr.get("all_strings", []))
                    if fr.get("entropy", 0) > 7.0:
                        entropy_findings.append({
                            "file": fr["filename"],
                            "entropy": fr["entropy"],
                            "filepath": fr["filepath"]
                        })
        
        # Categorize all extracted strings
        categorized = categorize_extracted_strings(all_strings)
        
        # Build analysis payload with network focus
        analysis_data = {
            "category": "network_indicators",
            "network_strings": categorized.get("network", []),
            "obfuscated_strings": categorized.get("obfuscated", []),
            "high_entropy_files": entropy_findings,
            "total_strings_analyzed": len(all_strings)
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


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
        all_strings = []
        high_entropy_files = []
        
        for category in ["TempFolder", "Downloads"]:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=25)
                for fr in file_results:
                    all_strings.extend(fr.get("all_strings", []))
                    if fr.get("entropy", 0) > 6.8:
                        high_entropy_files.append({
                            "file": fr["filename"],
                            "entropy": fr["entropy"],
                            "size": fr["size_bytes"],
                            "filepath": fr["filepath"]
                        })
        
        # Try decoding Base64 strings
        decoded_payloads = []
        for s in all_strings:
            if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', s):
                decoded = try_decode_base64(s)
                if decoded:
                    decoded_payloads.append({"original": s[:100], "decoded": decoded[:200]})
        
        categorized = categorize_extracted_strings(all_strings)
        
        analysis_data = {
            "category": "obfuscated_payloads",
            "obfuscated_strings": categorized.get("obfuscated", [])[:100],
            "decoded_base64_payloads": decoded_payloads[:20],
            "high_entropy_files": sorted(high_entropy_files, key=lambda x: x["entropy"], reverse=True)[:15],
            "total_strings_analyzed": len(all_strings)
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


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
        all_strings = []
        
        for category in ["TempFolder", "Downloads", "StartupFolders", "ScheduledTasks"]:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=15)
                for fr in file_results:
                    all_strings.extend(fr.get("all_strings", []))
        
        categorized = categorize_extracted_strings(all_strings)
        
        # Prioritize command execution strings
        command_strings = categorized.get("commands", [])
        path_strings = categorized.get("paths_registry", [])
        
        analysis_data = {
            "category": "command_execution",
            "command_execution_strings": command_strings[:150],
            "related_paths": path_strings[:100],
            "system_artifacts": categorized.get("system_artifacts", [])[:50],
            "total_strings_analyzed": len(all_strings)
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


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
        all_strings = []
        
        for category in ["TempFolder", "Downloads", "StartupFolders", "RecycleBin"]:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=20)
                for fr in file_results:
                    all_strings.extend(fr.get("all_strings", []))
        
        categorized = categorize_extracted_strings(all_strings)
        
        analysis_data = {
            "category": "paths_and_registry",
            "registry_paths": [s for s in categorized.get("paths_registry", []) if "HK" in s][:100],
            "file_drop_locations": [s for s in categorized.get("paths_registry", []) if "HK" not in s][:100],
            "cryptocurrency_addresses": categorized.get("cryptocurrency", [])[:30],
            "total_strings_analyzed": len(all_strings)
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


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
        all_strings = []
        
        for category in ["TempFolder", "Downloads"]:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=30)
                for fr in file_results:
                    all_strings.extend(fr.get("all_strings", []))
        
        categorized = categorize_extracted_strings(all_strings)
        
        # Extract PDB paths and developer info
        pdb_paths = [s for s in categorized.get("debug_metadata", []) if ".pdb" in s.lower()]
        compiler_info = [s for s in categorized.get("debug_metadata", []) if any(x in s.lower() for x in ["visual studio", "gcc", "clang", "msvc"])]
        
        analysis_data = {
            "category": "debug_metadata",
            "pdb_paths": pdb_paths[:50],
            "compiler_signatures": compiler_info[:30],
            "other_metadata": [s for s in categorized.get("debug_metadata", []) if s not in pdb_paths and s not in compiler_info][:50],
            "uncategorized_long_strings": categorized.get("uncategorized", [])[:100],
            "total_strings_analyzed": len(all_strings)
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


# ===========================================================================
# 3. MAIN COMPOSITE AGENT (FOR BACKWARDS COMPATIBILITY & MASTER ORCHESTRATION)
# ===========================================================================

class StringsAnalysisAgent(BaseHITLAgent):
    """
    File Analysis - Main Strings Analyzer Master Agent
    Developer Owner: [ N ]
    
    Orchestrates string extraction and deep LLM evaluation across ASCII/Unicode strings,
    C2 IPs/URLs, registry keys, Base64 payloads, execution strings, and debug metadata.
    Performs actual binary string extraction with entropy analysis and pattern detection.
    """
    def __init__(self):
        super().__init__(
            agent_name="Strings_Analyzer",
            system_prompt=(
                "You are a Lead Reverse Engineer performing comprehensive string analysis on target binaries. "
                "Analyze ASCII and Unicode strings for Indicators of Compromise (IOCs): C2 IP addresses, domains, "
                "URL paths, hardcoded encryption keys, user-agent strings, suspicious registry locations, "
                "PowerShell/cmd.exe execution strings, base64/hex obfuscated data, PDB build paths, "
                "cryptocurrency addresses, and WinAPI calls. Prioritize high-entropy files indicating packing/encryption."
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
        Processes File Analysis artifacts from the staging directory.
        Extracts strings from binaries in multiple categories and performs comprehensive analysis.
        """
        all_strings = []
        all_entropy_findings = []
        file_summaries = []
        
        # Extract strings from binaries across multiple relevant categories
        categories_to_scan = ["TempFolder", "Downloads", "StartupFolders", "RecycleBin"]
        
        for category in categories_to_scan:
            cat_path = staging_root / category / "raw"
            if cat_path.exists():
                file_results = extract_strings_from_directory(cat_path, min_len=4, max_files=25)
                for fr in file_results:
                    if fr.get("error"):
                        continue
                    
                    file_summaries.append({
                        "filename": fr["filename"],
                        "filepath": fr["filepath"],
                        "size_bytes": fr["size_bytes"],
                        "entropy": fr["entropy"],
                        "string_count": len(fr.get("all_strings", []))
                    })
                    
                    all_strings.extend(fr.get("all_strings", []))
                    
                    # Flag high entropy files (possible packing/encryption)
                    if fr.get("entropy", 0) > 6.5:
                        all_entropy_findings.append({
                            "file": fr["filename"],
                            "entropy": fr["entropy"],
                            "filepath": fr["filepath"],
                            "size": fr["size_bytes"]
                        })
        
        # Categorize all extracted strings
        categorized = categorize_extracted_strings(all_strings)
        
        # Identify decoded Base64 payloads
        decoded_payloads = []
        for s in categorized.get("obfuscated", []):
            if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', s):
                decoded = try_decode_base64(s)
                if decoded:
                    decoded_payloads.append({"original": s[:100], "decoded": decoded[:200]})
        
        # Build comprehensive analysis report
        analysis_data = {
            "category": "comprehensive_string_analysis",
            "files_analyzed": len(file_summaries),
            "file_summaries": sorted(file_summaries, key=lambda x: x["entropy"], reverse=True)[:30],
            "total_strings_extracted": len(all_strings),
            "high_entropy_files": sorted(all_entropy_findings, key=lambda x: x["entropy"], reverse=True)[:20],
            "categorized_strings": {
                "network_indicators": categorized.get("network", [])[:150],
                "obfuscated_strings": categorized.get("obfuscated", [])[:100],
                "command_execution": categorized.get("commands", [])[:150],
                "paths_registry": categorized.get("paths_registry", [])[:150],
                "debug_metadata": categorized.get("debug_metadata", [])[:100],
                "cryptocurrency": categorized.get("cryptocurrency", [])[:30],
                "system_artifacts": categorized.get("system_artifacts", [])[:80],
                "uncategorized": categorized.get("uncategorized", [])[:100]
            },
            "decoded_base64_payloads": decoded_payloads[:20],
            "analysis_summary": {
                "network_iocs_found": len(categorized.get("network", [])),
                "obfuscated_strings_found": len(categorized.get("obfuscated", [])),
                "command_strings_found": len(categorized.get("commands", [])),
                "registry_paths_found": len(categorized.get("paths_registry", [])),
                "high_entropy_files_count": len(all_entropy_findings),
                "crypto_addresses_found": len(categorized.get("cryptocurrency", []))
            }
        }
        
        return await self.run_with_hitl(parsed_tool_data=json.dumps(analysis_data))


# ===========================================================================
# 4. CLI ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = StringsAnalysisAgent()
    asyncio.run(agent.process_task(staging_root))
