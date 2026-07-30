import os
import re
import json
import struct
import math
import hashlib
import asyncio
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


_SUSPICIOUS_API_CATEGORIES = {
    "process_injection": [
        "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread", "OpenProcess",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "ResumeThread", "NtCreateThreadEx", "RtlCreateUserThread",
    ],
    "anti_debug_evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "ZwQuerySystemInformation", "NtClose", "NtRaiseHardError",
        "SetUnhandledExceptionFilter", "RaiseException",
    ],
    "persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx",
        "SHGetSpecialFolderLocation", "SHGetFolderPath", "SHSetValue",
        "CreateService", "StartService", "OpenSCManager",
        "ChangeServiceConfig", "DeleteService",
    ],
    "code_execution": [
        "WinExec", "CreateProcess", "CreateProcessAsUser",
        "ShellExecute", "ShellExecuteEx", "NtCreateProcess",
        "system", "popen", "_wsystem",
    ],
    "network_communication": [
        "socket", "connect", "send", "recv", "WSASocket",
        "WSASocket", "WSAConnect", "WSASend", "WSARecv",
        "gethostbyname", "getaddrinfo", "WSAStartup",
        "InternetOpen", "InternetConnect", "HttpOpenRequest",
        "HttpSendRequest", "InternetReadFile", "InternetWriteFile",
        "URLDownloadToFile", "URLDownloadToCacheFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
        "FtpGetFile", "FtpPutFile",
    ],
    "cryptography": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
        "CryptAcquireContext", "CryptReleaseContext", "CryptDestroyKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptSetProperty", "BCryptImportKey",
    ],
    "keylogging_capture": [
        "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow",
        "GetWindowText", "GetWindowTextLength", "GetClipboardData",
        "SetClipboardData", "RegisterClipboardFormat",
    ],
    "dynamic_resolution": [
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll",
        "LdrGetProcedureAddress", "GetModuleHandleA", "GetModuleHandleW",
    ],
    "injection_support": [
        "SetWindowsHookEx", "SetWinEventHook",
        "ZwWriteVirtualMemory", "ZwReadVirtualMemory",
        "ZwProtectVirtualMemory", "ZwAllocateVirtualMemory",
        "MapViewOfFile", "CreateFileMapping",
    ],
}

_SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".upx", ".packed",
    ".aspack", ".adata", ".MPR1", ".MPR2",
    ".petext", ".nsp0", ".nsp1", ".nsp2",
    ".pec0", ".pec1", ".pec2", ".pdata",
    ".boot", ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".enigma", ".confused", ".ccg",
}

_RARE_SECTION_NAMES = {
    ".00cfg", ".explik", ".txt", ".data2", ".mackt",
    ".ops", ".orpc", ".PEGABO0", ".PEGABO1", ".PEGABO2",
    ".prtext", ".rtext", ".s1", ".s2", ".s7",
    ".tsr", ".texti", ".tls", ".udata", ".vmp",
    ".winap", ".y0", ".y1", ".y2", ".y3", ".y4",
    ".y5", ".y6", ".y7", ".y8", ".y9",
}

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack("<H", data[offset:offset+2])[0]

def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack("<I", data[offset:offset+4])[0]

def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack("<Q", data[offset:offset+8])[0]

def _read_null_terminated_string(data: bytes, offset: int, max_len: int = 256) -> str:
    end = offset
    while end < len(data) and end - offset < max_len and data[end] != 0:
        end += 1
    return data[offset:end].decode("utf-8", errors="replace")

def _rva_to_offset(rva: int, sections: List[Dict]) -> Optional[int]:
    for sec in sections:
        sec_va = sec["virtual_address"]
        sec_size = sec["virtual_size"]
        sec_raw = sec["pointer_to_raw_data"]
        if sec_va <= rva < sec_va + sec_size:
            return rva - sec_va + sec_raw
    return None

def _calculate_shannon_entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    entropy = 0.0
    chunk_len = len(chunk)
    for c in range(256):
        p = chunk.count(c) / chunk_len
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def _parse_pe(data: bytes) -> Optional[Dict]:
    if len(data) < 64:
        return None
    if data[0:2] != b"MZ":
        return None
    pe_offset = _read_u32(data, 0x3C)
    if pe_offset + 4 > len(data):
        return None
    if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        return None
    result: Dict[str, Any] = {}
    nh_offset = pe_offset + 4
    if nh_offset + 20 > len(data):
        return None
    result["machine"] = _read_u16(data, nh_offset)
    result["number_of_sections"] = _read_u16(data, nh_offset + 2)
    result["time_date_stamp"] = _read_u32(data, nh_offset + 4)
    result["size_of_optional_header"] = _read_u16(data, nh_offset + 16)
    result["characteristics"] = _read_u16(data, nh_offset + 18)
    num_sections = result["number_of_sections"]
    opt_header_size = result["size_of_optional_header"]
    oh_offset = nh_offset + 20
    if oh_offset + 2 > len(data):
        return None
    magic = _read_u16(data, oh_offset)
    result["pe_type"] = "PE32" if magic == 0x10B else "PE32+" if magic == 0x20B else "UNKNOWN"
    dd_offset = oh_offset + (96 if magic == 0x10B else 112)
    result["data_directories"] = {}
    if dd_offset + 8 * 16 <= len(data):
        export_rva = _read_u32(data, dd_offset + 0)
        export_size = _read_u32(data, dd_offset + 4)
        import_rva = _read_u32(data, dd_offset + 8)
        import_size = _read_u32(data, dd_offset + 12)
        result["data_directories"]["export"] = {"rva": export_rva, "size": export_size}
        result["data_directories"]["import"] = {"rva": import_rva, "size": import_size}
    sec_table_offset = oh_offset + opt_header_size
    sections = []
    for i in range(num_sections):
        sec_off = sec_table_offset + i * 40
        if sec_off + 40 > len(data):
            break
        raw_name = data[sec_off:sec_off+8]
        sec_name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")
        section = {
            "index": i,
            "name": sec_name if sec_name else f"[unnamed_{i}]",
            "virtual_size": _read_u32(data, sec_off + 8),
            "virtual_address": _read_u32(data, sec_off + 12),
            "size_of_raw_data": _read_u32(data, sec_off + 16),
            "pointer_to_raw_data": _read_u32(data, sec_off + 20),
            "characteristics": _read_u32(data, sec_off + 36),
        }
        raw_off = section["pointer_to_raw_data"]
        raw_size = section["size_of_raw_data"]
        if raw_off > 0 and raw_size > 0 and raw_off + raw_size <= len(data):
            section_data = data[raw_off:raw_off + raw_size]
            section["entropy"] = _calculate_shannon_entropy(section_data)
        else:
            section["entropy"] = 0.0
        sections.append(section)
    result["sections"] = sections
    imports = []
    imp_dir = result["data_directories"].get("import", {})
    imp_rva = imp_dir.get("rva", 0)
    imp_size = imp_dir.get("size", 0)
    if imp_rva and imp_size and sections:
        imp_offset = _rva_to_offset(imp_rva, sections)
        if imp_offset is not None:
            descriptor_size = 20
            desc_offset = imp_offset
            while desc_offset + descriptor_size <= len(data):
                original_first_thunk = _read_u32(data, desc_offset)
                time_date_stamp = _read_u32(data, desc_offset + 4)
                forwarder_chain = _read_u32(data, desc_offset + 8)
                name_rva = _read_u32(data, desc_offset + 12)
                first_thunk = _read_u32(data, desc_offset + 16)
                if original_first_thunk == 0 and name_rva == 0:
                    break
                orig_offset = _rva_to_offset(original_first_thunk, sections) if original_first_thunk else _rva_to_offset(first_thunk, sections)
                name_offset = _rva_to_offset(name_rva, sections) if name_rva else None
                dll_name = _read_null_terminated_string(data, name_offset) if name_offset else "UNKNOWN"
                imports_apis = []
                if orig_offset is not None:
                    is_64bit = result["pe_type"] == "PE32+"
                    thunk_size = 8 if is_64bit else 4
                    thunk_offset = orig_offset
                    while True:
                        if is_64bit:
                            thunk_val = _read_u64(data, thunk_offset)
                            thunk_offset += 8
                        else:
                            thunk_val = _read_u32(data, thunk_offset)
                            thunk_offset += 4
                        if thunk_val == 0:
                            break
                        if thunk_val & (1 << 63 if is_64bit else 1 << 31):
                            ordinal = thunk_val & 0xFFFF if is_64bit else thunk_val & 0x7FFFFFFF
                            imports_apis.append(f"ORDINAL_{ordinal}")
                        else:
                            import_name_offset = _rva_to_offset(thunk_val, sections)
                            if import_name_offset:
                                hint = _read_u16(data, import_name_offset)
                                api_name = _read_null_terminated_string(data, import_name_offset + 2)
                                imports_apis.append(api_name)
                imports.append({
                    "dll_name": dll_name.replace(".dll", "").lower(),
                    "imports": imports_apis,
                    "count": len(imports_apis),
                })
                desc_offset += descriptor_size
    result["imports"] = imports
    exports = []
    exp_dir = result["data_directories"].get("export", {})
    exp_rva = exp_dir.get("rva", 0)
    exp_size = exp_dir.get("size", 0)
    if exp_rva and exp_size and sections:
        exp_offset = _rva_to_offset(exp_rva, sections)
        if exp_offset is not None and exp_offset + 40 <= len(data):
            export_base = _read_u32(data, exp_offset + 16)
            num_functions = _read_u32(data, exp_offset + 20)
            num_names = _read_u32(data, exp_offset + 24)
            addr_of_funcs = _read_u32(data, exp_offset + 28)
            addr_of_names = _read_u32(data, exp_offset + 32)
            addr_of_ordinals = _read_u32(data, exp_offset + 36)
            names_offset = _rva_to_offset(addr_of_names, sections)
            ordinals_offset = _rva_to_offset(addr_of_ordinals, sections)
            funcs_offset = _rva_to_offset(addr_of_funcs, sections)
            if names_offset is not None and ordinals_offset is not None and funcs_offset is not None:
                for i in range(min(num_names, 256)):
                    name_rva = _read_u32(data, names_offset + i * 4)
                    ordinal = _read_u16(data, ordinals_offset + i * 2)
                    name_off = _rva_to_offset(name_rva, sections)
                    if name_off:
                        func_name = _read_null_terminated_string(data, name_off)
                        exports.append({"name": func_name, "ordinal": ordinal + export_base})
    result["exports"] = exports
    return result

def _analyze_timestamp(timestamp: int) -> Dict:
    import datetime
    if timestamp == 0:
        return {"suspicious": True, "reason": "Timestamp is zero (not set / deliberately cleared)"}
    if timestamp == 0xFFFFFFFF:
        return {"suspicious": True, "reason": "Timestamp is 0xFFFFFFFF (deliberately invalid)"}
    try:
        dt = datetime.datetime.utcfromtimestamp(timestamp)
        now = datetime.datetime.utcnow()
        if dt > now:
            return {"suspicious": True, "reason": f"Timestamp is in the future: {dt.isoformat()}"}
        if dt.year < 2000:
            return {"suspicious": True, "reason": f"Timestamp is unusually old: {dt.isoformat()}"}
        return {"suspicious": False, "reason": f"Normal compilation timestamp: {dt.isoformat()}"}
    except Exception:
        return {"suspicious": False, "reason": "Could not parse timestamp"}

def _categorize_api(api_name: str) -> List[str]:
    categories = []
    for category, apis in _SUSPICIOUS_API_CATEGORIES.items():
        if any(susp_api.lower() == api_name.lower() for susp_api in apis):
            categories.append(category)
    return categories

def _analyze_sections(sections: List[Dict]) -> List[Dict]:
    findings = []
    for sec in sections:
        name = sec["name"]
        if name.lower() in {s.lower() for s in _SUSPICIOUS_SECTION_NAMES}:
            findings.append({"section": name, "type": "known_packer_section", "severity": "High",
                             "detail": f"Section name '{name}' matches known packer/crypter pattern."})
        elif name.lower() in {s.lower() for s in _RARE_SECTION_NAMES}:
            findings.append({"section": name, "type": "rare_section_name", "severity": "Medium",
                             "detail": f"Section name '{name}' is rarely seen in legitimate software."})
        chars = sec.get("characteristics", 0)
        is_exec = bool(chars & _IMAGE_SCN_MEM_EXECUTE)
        is_write = bool(chars & _IMAGE_SCN_MEM_WRITE)
        if is_exec and is_write:
            findings.append({"section": name, "type": "writable_executable_section", "severity": "High",
                             "detail": f"Section '{name}' is both writable and executable (flags: 0x{chars:08X})."})
        entropy = sec.get("entropy", 0)
        if entropy > 7.5:
            findings.append({"section": name, "type": "high_entropy_section", "severity": "High",
                             "detail": f"Section '{name}' has entropy {entropy:.2f} (packed/encrypted)."})
        elif entropy > 7.0:
            findings.append({"section": name, "type": "elevated_entropy_section", "severity": "Medium",
                             "detail": f"Section '{name}' has entropy {entropy:.2f} (possibly compressed/obfuscated)."})
        if sec.get("virtual_size", 0) == 0:
            findings.append({"section": name, "type": "zero_virtual_size", "severity": "Low",
                             "detail": f"Section '{name}' has virtual size of 0 bytes."})
    return findings

def _analyze_imports(imports: List[Dict]) -> Dict:
    categorized: Dict[str, List[Dict]] = {}
    total_suspicious = 0
    dll_list = []
    for imp in imports:
        dll_name = imp["dll_name"]
        if dll_name not in dll_list:
            dll_list.append(dll_name)
        for api in imp["imports"]:
            cats = _categorize_api(api)
            if cats:
                total_suspicious += 1
                for cat in cats:
                    if cat not in categorized:
                        categorized[cat] = []
                    categorized[cat].append(f"{dll_name}.{api}")
    return {
        "dlls_count": len(dll_list),
        "dlls": sorted(dll_list),
        "import_count": sum(imp["count"] for imp in imports),
        "total_suspicious_apis": total_suspicious,
        "suspicious_by_category": categorized,
        "notable_dlls": {
            "has_ws2_32": "ws2_32" in dll_list or "wsock32" in dll_list,
            "has_winhttp": "winhttp" in dll_list,
            "has_wininet": "wininet" in dll_list,
            "has_crypt32": "crypt32" in dll_list or "bcrypt" in dll_list,
            "has_urlmon": "urlmon" in dll_list,
        },
    }

def _analyze_exports(exports: List[Dict]) -> Dict:
    return {"export_count": len(exports), "sample": [e["name"] for e in exports[:20]], "truncated": len(exports) > 20}

def _generate_indicators(pe_data: Dict, section_findings: List[Dict], import_analysis: Dict) -> List[Dict]:
    indicators = []
    indicator_set = set()

    def add_indicator(ind_type: str, severity: str, detail: str):
        key = f"{ind_type}:{detail}"
        if key not in indicator_set:
            indicator_set.add(key)
            indicators.append({"type": ind_type, "severity": severity, "detail": detail})

    for f in section_findings:
        add_indicator(f["type"], f["severity"], f["detail"])

    if import_analysis["total_suspicious_apis"] >= 10:
        add_indicator("heavy_suspicious_imports", "High",
                       f"Binary imports {import_analysis['total_suspicious_apis']} suspicious API calls.")
    elif import_analysis["total_suspicious_apis"] > 0:
        cats = list(import_analysis["suspicious_by_category"].keys())
        add_indicator("suspicious_imports", "Medium",
                       f"Binary imports {import_analysis['total_suspicious_apis']} suspicious APIs in: {', '.join(cats)}.")

    notable = import_analysis.get("notable_dlls", {})
    if notable.get("has_ws2_32") and notable.get("has_winhttp"):
        add_indicator("network_capable", "Medium",
                       "Binary imports both socket (ws2_32) and HTTP (winhttp/WinINet) libraries.")
    if notable.get("has_crypt32"):
        add_indicator("crypto_capable", "Medium",
                       "Binary imports cryptography libraries (crypt32/BCrypt).")

    rwx_sections = [f for f in section_findings if f["type"] == "writable_executable_section"]
    if rwx_sections:
        add_indicator("rwx_sections_present", "Critical",
                       f"Binary has {len(rwx_sections)} RWX sections -- shellcode injection or packed code.")

    high_entropy = [f for f in section_findings if f["type"] == "high_entropy_section"]
    if high_entropy:
        add_indicator("packing_detected", "High",
                       f"Binary has {len(high_entropy)} high-entropy sections -- packed or encrypted.")

    ts = pe_data.get("time_date_stamp", 0)
    ts_analysis = _analyze_timestamp(ts)
    if ts_analysis.get("suspicious"):
        add_indicator("suspicious_timestamp", "Medium", ts_analysis["reason"])

    return indicators

def _build_pestudio_payload(staging_root: Path, hash_fn, truncate_fn) -> str:
    binary_extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv"}
    max_file_size = 50_000_000
    max_binaries = 20
    findings = []
    total_scanned = 0
    total_skipped = 0

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
                if total_scanned >= max_binaries:
                    break
                try:
                    stats = fpath.stat()
                except Exception:
                    continue
                if stats.st_size > max_file_size:
                    total_skipped += 1
                    findings.append({"filepath": str(fpath.relative_to(staging_root)), "filename": fname,
                                     "size_bytes": stats.st_size, "skipped": True,
                                     "skip_reason": "File exceeds 50MB size limit for PE analysis"})
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                except Exception:
                    total_skipped += 1
                    continue
                total_scanned += 1
                pe_data = _parse_pe(data)
                if pe_data is None:
                    findings.append({"filepath": str(fpath.relative_to(staging_root)), "filename": fname,
                                     "size_bytes": stats.st_size, "skipped": True,
                                     "skip_reason": "Not a valid PE file or unreadable"})
                    continue
                hashes = hash_fn(fpath)
                section_findings = _analyze_sections(pe_data.get("sections", []))
                import_analysis = _analyze_imports(pe_data.get("imports", []))
                export_analysis = _analyze_exports(pe_data.get("exports", []))
                ts_analysis = _analyze_timestamp(pe_data.get("time_date_stamp", 0))
                indicators = _generate_indicators(pe_data, section_findings, import_analysis)
                findings.append({
                    "filepath": str(fpath.relative_to(staging_root)), "filename": fname,
                    "size_bytes": stats.st_size, "extension": ext, "hashes": hashes, "skipped": False,
                    "pe_header": {
                        "machine": pe_data.get("machine"), "pe_type": pe_data.get("pe_type"),
                        "characteristics": pe_data.get("characteristics"),
                        "time_date_stamp": pe_data.get("time_date_stamp"),
                        "timestamp_analysis": ts_analysis,
                        "number_of_sections": pe_data.get("number_of_sections"),
                    },
                    "sections": [{"name": s["name"], "virtual_size": s["virtual_size"],
                                  "virtual_address": hex(s["virtual_address"]),
                                  "raw_size": s["size_of_raw_data"], "entropy": s["entropy"],
                                  "characteristics": hex(s.get("characteristics", 0))}
                                 for s in pe_data.get("sections", [])],
                    "imports": import_analysis, "exports": export_analysis,
                    "section_findings": section_findings, "indicators": indicators,
                })
            if total_scanned >= max_binaries:
                break
    payload = {
        "analysis_type": "pestudio_static_pe_analysis", "staging_root": str(staging_root),
        "total_binaries_analyzed": total_scanned, "total_binaries_skipped": total_skipped,
        "note": "PE static analysis using safe header parsing. No binary was disassembled or executed.",
        "findings": findings,
    }
    return truncate_fn(json.dumps(payload, indent=2))


class PeStudioAnalysisAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="PeStudio_Static_Triage_Analyzer",
            system_prompt=(
                "You are a Malware Analyst performing static PE triage on executable binaries. "
                "You are given structured PE metadata including section tables with Shannon entropy, "
                "import/export directories, compilation timestamps, and pre-computed suspicious indicators. "
                "Analyze each binary and provide a comprehensive assessment covering:\n"
                "1. Packing / Obfuscation: High-entropy sections, unusual section names, RWX permissions.\n"
                "2. Suspicious Imports: APIs used for process injection, anti-debugging, persistence, and network communication.\n"
                "3. Compilation Timestamp: Evaluate whether the timestamp is plausible, blanked, or suspicious.\n"
                "4. Import-Based Capabilities: Does the binary have network, crypto, keylogging, or injection capabilities?\n"
                "5. Export Analysis: Any unusual exported functions or ordinals?\n"
                "6. Overall Risk: Classify each binary as Clean, Suspicious, or Critical with justification.\n"
                "Focus on actionable forensic indicators -- flag behaviors, not just presence of APIs."
            ),
        )

    async def process_task(self, staging_root: Path):
        payload = _build_pestudio_payload(staging_root, self._calculate_file_hashes, self._truncate_payload)
        return await self.run_with_hitl(parsed_tool_data=payload)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = PeStudioAnalysisAgent()
    asyncio.run(agent.process_task(staging_root))
