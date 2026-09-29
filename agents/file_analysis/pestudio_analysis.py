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
from core.models import FileHashSet, MitreMapping, StaticAnalysisReport
from core.utils import locate_staging_directory
from core import yara_engine
from . import mcp_client


_YARA_MAX_FILE_SIZE = 50_000_000
_YARA_MAX_FILES = 200


def _yara_scan_staging_root(staging_root: Path) -> List[Dict[str, Any]]:
    """Runs every active YARA rule (managed from the Management page) against
    every raw evidence file under staging_root -- not just PE/ELF binaries,
    since YARA rules commonly target scripts/text payloads too. Independent
    of the PE/ELF parsing path above so a bad YARA rule can never affect
    binary triage."""
    anomalies = []
    scanned = 0
    for category_dir in staging_root.iterdir():
        if not category_dir.is_dir() or scanned >= _YARA_MAX_FILES:
            continue
        raw_dir = category_dir / "raw"
        if not raw_dir.exists():
            continue
        for root, _, files in os.walk(raw_dir):
            for fname in files:
                if scanned >= _YARA_MAX_FILES:
                    break
                fpath = Path(root) / fname
                try:
                    if fpath.stat().st_size > _YARA_MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                scanned += 1
                for match in yara_engine.scan_file(str(fpath)):
                    severity = match["meta"].get("severity", "High")
                    anomalies.append({
                        "filepath": str(fpath.relative_to(staging_root)),
                        "anomaly_type": f"YARA Match: {match['rule_name']}",
                        "severity": severity if severity in ("Critical", "High", "Medium", "Low") else "High",
                        "justification": match["meta"].get("description", f"Matched YARA rule '{match['rule_name']}'"
                                          f"{' (' + ', '.join(match['tags']) + ')' if match['tags'] else ''}."),
                        "recommended_action": "Review the matched rule's intent and escalate for manual analysis.",
                    })
    return anomalies


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

def compute_imphash(imports: List[Dict]) -> Optional[str]:
    """PE import hash: md5 of 'dllname.apiname,dllname.apiname,...' (DLL
    names lowercased with extension stripped, ordinal imports as 'ordN'),
    in declared order -- the same algorithm pefile/VirusTotal's imphash uses,
    computed here directly from the import table _parse_pe() already walked
    (no pefile dependency needed)."""
    if not imports:
        return None
    parts = []
    for imp in imports:
        dll = imp.get("dll_name", "").lower()
        for api in imp.get("imports", []):
            if api.startswith("ORDINAL_"):
                parts.append(f"{dll}.ord{api.split('_', 1)[1]}")
            else:
                parts.append(f"{dll}.{api.lower()}")
    if not parts:
        return None
    return hashlib.md5(",".join(parts).encode("utf-8")).hexdigest()


def compute_ssdeep(fpath: Path) -> Optional[str]:
    """Fuzzy hash for near-duplicate/variant matching against known-malware
    corpora. Best-effort: the `ssdeep` package needs the native libfuzzy
    library, which isn't available in every environment -- absence degrades
    to None rather than failing the whole triage."""
    try:
        import ssdeep
        return ssdeep.hash_from_file(str(fpath))
    except Exception:
        return None


_ELF_CLASS = {1: 32, 2: 64}
_ELF_MACHINE = {0x03: "x86", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64"}


def _parse_elf(data: bytes) -> Optional[Dict]:
    """Lightweight ELF parser: header, section table, and the dynamic symbol
    table (.dynsym/.dynstr) for the "shape of imports" typehash and a basic
    import/needed-library listing. Deliberately not a full relocation/PLT
    resolver -- this is triage depth, matching the PE path's ambition level,
    not a disassembler."""
    if len(data) < 64 or data[0:4] != b"\x7fELF":
        return None
    ei_class = data[4]
    ei_data = data[5]  # 1 = little-endian, 2 = big-endian
    if ei_class not in _ELF_CLASS or ei_data != 1:
        return None
    is64 = ei_class == 2
    endian = "<"

    def u16(off): return struct.unpack(endian + "H", data[off:off + 2])[0]
    def u32(off): return struct.unpack(endian + "I", data[off:off + 4])[0]
    def u64(off): return struct.unpack(endian + "Q", data[off:off + 8])[0]
    def addr(off): return u64(off) if is64 else u32(off)

    e_type = u16(16)
    e_machine = u16(18)
    e_shoff = addr(0x28) if is64 else addr(0x20)
    e_shentsize = u16(0x3A if is64 else 0x2E)
    e_shnum = u16(0x3C if is64 else 0x30)
    e_shstrndx = u16(0x3E if is64 else 0x32)

    result: Dict[str, Any] = {
        "elf_class": _ELF_CLASS[ei_class], "machine": _ELF_MACHINE.get(e_machine, hex(e_machine)),
        "elf_type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type)),
    }

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + (64 if is64 else 40) > len(data):
            break
        if is64:
            sh_name = u32(off)
            sh_type = u32(off + 4)
            sh_offset = u64(off + 24)
            sh_size = u64(off + 32)
            sh_link = u32(off + 40)
        else:
            sh_name = u32(off)
            sh_type = u32(off + 4)
            sh_offset = u32(off + 16)
            sh_size = u32(off + 20)
            sh_link = u32(off + 24)
        sections.append({"name_off": sh_name, "type": sh_type, "offset": sh_offset, "size": sh_size, "link": sh_link})

    def _read_strtab(strtab_off: int, strtab_size: int, name_off: int) -> str:
        base = strtab_off + name_off
        if base >= strtab_off + strtab_size or base >= len(data):
            return ""
        return _read_null_terminated_string(data, base)

    shstrtab = sections[e_shstrndx] if 0 <= e_shstrndx < len(sections) else None
    named_sections = []
    if shstrtab and shstrtab["offset"] + shstrtab["size"] <= len(data):
        for sec in sections:
            name = _read_strtab(shstrtab["offset"], shstrtab["size"], sec["name_off"])
            sec_data = data[sec["offset"]:sec["offset"] + sec["size"]] if sec["type"] != 8 else b""  # type 8 = NOBITS
            named_sections.append({
                "name": name or "[unnamed]", "size": sec["size"], "type": sec["type"],
                "entropy": _calculate_shannon_entropy(sec_data) if sec_data else 0.0,
            })
    result["sections"] = named_sections

    # Dynamic symbol table -> imported (undefined) symbol names, the ELF
    # analog of a PE import table for typehash purposes.
    dynsym = next((s for s in sections if s["type"] == 11), None)  # SHT_DYNSYM
    dynstr_idx = dynsym["link"] if dynsym else None
    dynstr = sections[dynstr_idx] if dynsym and dynstr_idx is not None and dynstr_idx < len(sections) else None
    imported_symbols = []
    if dynsym and dynstr:
        sym_entry_size = 24 if is64 else 16
        sym_count = dynsym["size"] // sym_entry_size if sym_entry_size else 0
        for i in range(min(sym_count, 2000)):
            sym_off = dynsym["offset"] + i * sym_entry_size
            if sym_off + sym_entry_size > len(data):
                break
            name_idx = u32(sym_off)
            shndx = u16(sym_off + (6 if is64 else 14))
            if name_idx == 0 or shndx != 0:  # SHN_UNDEF (0) == imported/external symbol
                continue
            name = _read_strtab(dynstr["offset"], dynstr["size"], name_idx)
            if name:
                imported_symbols.append(name)
    result["imported_symbols"] = sorted(set(imported_symbols))
    return result


def compute_typehash(imported_symbols: List[str]) -> Optional[str]:
    """ELF analog of imphash: md5 of the sorted, deduplicated list of
    imported (undefined) dynamic symbol names -- the "shape of imports"
    signature used to cluster ELF variants sharing a linkage profile."""
    if not imported_symbols:
        return None
    return hashlib.md5(",".join(sorted(set(imported_symbols))).encode("utf-8")).hexdigest()


def _analyze_elf_indicators(elf_data: Dict) -> List[Dict]:
    indicators = []
    for sec in elf_data.get("sections", []):
        entropy = sec.get("entropy", 0)
        if entropy > 7.5:
            indicators.append({"type": "high_entropy_section", "severity": "High",
                               "detail": f"ELF section '{sec['name']}' has entropy {entropy:.2f} (packed/encrypted)."})
        elif entropy > 7.0:
            indicators.append({"type": "elevated_entropy_section", "severity": "Medium",
                               "detail": f"ELF section '{sec['name']}' has entropy {entropy:.2f}."})
    suspicious_elf_symbols = {"ptrace", "dlopen", "dlsym", "mprotect", "memfd_create", "execve", "fork", "socket", "connect"}
    hits = sorted(s for s in elf_data.get("imported_symbols", []) if s in suspicious_elf_symbols)
    if hits:
        indicators.append({"type": "suspicious_imports", "severity": "Medium",
                           "detail": f"ELF imports sensitive libc/syscall wrappers: {', '.join(hits)}."})
    return indicators


async def _capa_capabilities_for_file(fpath: Path) -> List[MitreMapping]:
    """CAPA MCP call for one binary -- mapped defensively since the exact
    response schema is server-dependent; every field is optional except the
    capability name itself."""
    response = await mcp_client.call_tool(mcp_client.CAPA_MCP, "analyze_capabilities", {"path": str(fpath)})
    capabilities = response.get("capabilities", []) if isinstance(response, dict) else []
    mappings = []
    for cap in capabilities:
        if not isinstance(cap, dict):
            continue
        name = cap.get("rule") or cap.get("name") or cap.get("capability")
        if not name:
            continue
        attack = cap.get("attack") or {}
        mappings.append(MitreMapping(
            capability=name,
            technique_id=cap.get("technique_id") or attack.get("id"),
            technique_name=cap.get("technique_name") or attack.get("technique"),
            tactic=cap.get("tactic") or attack.get("tactic"),
            confidence=cap.get("confidence", "Medium"),
            matched_addresses=[str(a) for a in (cap.get("matches") or cap.get("addresses") or [])],
        ))
    return mappings


def _indicators_to_severity_status(indicators: List[Dict], capa_capabilities: List[MitreMapping]) -> str:
    if any(i.get("severity") == "Critical" for i in indicators):
        return "Critical"
    if any(i.get("severity") in ("High", "Critical") for i in indicators) or len(capa_capabilities) >= 3:
        return "Suspicious" if not any(i.get("severity") == "Critical" for i in indicators) else "Critical"
    if indicators or capa_capabilities:
        return "Suspicious"
    return "Clean"


async def _build_static_triage_reports(staging_root: Path) -> List[Tuple[StaticAnalysisReport, Path]]:
    """Pure automation. Walks every category's raw/ for PE/ELF candidates and
    returns one fully-typed StaticAnalysisReport per binary (plus its path,
    for the Father Agent's conditional dynamic-analysis gate)."""
    binary_extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".ocx", ".drv", ".elf", ".so", ".bin"}
    max_file_size = 50_000_000
    max_binaries = 20
    reports: List[Tuple[StaticAnalysisReport, Path]] = []
    scanned = 0

    for category_dir in staging_root.iterdir():
        if not category_dir.is_dir() or scanned >= max_binaries:
            continue
        raw_dir = category_dir / "raw"
        if not raw_dir.exists():
            continue
        for root, _, files in os.walk(raw_dir):
            for fname in files:
                if scanned >= max_binaries:
                    break
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in binary_extensions:
                    continue
                try:
                    if fpath.stat().st_size > max_file_size:
                        continue
                    with open(fpath, "rb") as f:
                        data = f.read()
                except Exception:
                    continue

                pe_data = _parse_pe(data)
                elf_data = None if pe_data else _parse_elf(data)
                if pe_data is None and elf_data is None:
                    continue
                scanned += 1

                capa_capabilities = await _capa_capabilities_for_file(fpath)

                if pe_data is not None:
                    section_findings = _analyze_sections(pe_data.get("sections", []))
                    import_analysis = _analyze_imports(pe_data.get("imports", []))
                    indicators = _generate_indicators(pe_data, section_findings, import_analysis)
                    section_entropies = {s["name"]: s["entropy"] for s in pe_data.get("sections", [])}
                    hashes = FileHashSet(
                        **{k: v for k, v in self_calc_hashes(fpath).items() if k in ("md5", "sha256")},
                        ssdeep=compute_ssdeep(fpath),
                        imphash=compute_imphash(pe_data.get("imports", [])),
                    )
                    report = StaticAnalysisReport(
                        filepath=str(fpath.relative_to(staging_root)),
                        file_type="PE",
                        hashes=hashes,
                        overall_entropy=round(sum(section_entropies.values()) / len(section_entropies), 4) if section_entropies else 0.0,
                        section_entropies=section_entropies,
                        packing_suspected=any(i["type"] in ("high_entropy_section", "known_packer_section") for i in indicators),
                        suspicious_imports=import_analysis.get("suspicious_by_category", {}),
                        capa_capabilities=capa_capabilities,
                        indicators=indicators,
                        status=_indicators_to_severity_status(indicators, capa_capabilities),
                        summary=(
                            f"PE binary, {len(indicators)} deterministic indicator(s), "
                            f"{len(capa_capabilities)} CAPA capability match(es)."
                        ),
                    )
                else:
                    indicators = _analyze_elf_indicators(elf_data)
                    section_entropies = {s["name"]: s["entropy"] for s in elf_data.get("sections", [])}
                    hashes = FileHashSet(
                        **{k: v for k, v in self_calc_hashes(fpath).items() if k in ("md5", "sha256")},
                        ssdeep=compute_ssdeep(fpath),
                        typehash=compute_typehash(elf_data.get("imported_symbols", [])),
                    )
                    report = StaticAnalysisReport(
                        filepath=str(fpath.relative_to(staging_root)),
                        file_type="ELF",
                        hashes=hashes,
                        overall_entropy=round(sum(section_entropies.values()) / len(section_entropies), 4) if section_entropies else 0.0,
                        section_entropies=section_entropies,
                        packing_suspected=any(i["type"] == "high_entropy_section" for i in indicators),
                        suspicious_imports={},
                        capa_capabilities=capa_capabilities,
                        indicators=indicators,
                        status=_indicators_to_severity_status(indicators, capa_capabilities),
                        summary=(
                            f"ELF binary, {len(indicators)} deterministic indicator(s), "
                            f"{len(capa_capabilities)} CAPA capability match(es)."
                        ),
                    )
                reports.append((report, fpath))
            if scanned >= max_binaries:
                break
    return reports


def self_calc_hashes(fpath: Path) -> Dict[str, str]:
    """md5+sha256 only -- kept separate from BaseHITLAgent._calculate_file_hashes
    so this module's pure functions stay agent-instance-independent and unit-
    testable without constructing a BaseHITLAgent (which builds an LLM client)."""
    hasher_md5 = hashlib.md5()
    hasher_sha256 = hashlib.sha256()
    try:
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher_md5.update(chunk)
                hasher_sha256.update(chunk)
        return {"md5": hasher_md5.hexdigest(), "sha256": hasher_sha256.hexdigest()}
    except Exception:
        return {}


class StaticTriageAndCapabilityMapperAgent(BaseHITLAgent):
    """Pure automation -- never calls execute_llm_analysis(). See
    run_automated_with_hitl() in core/base_agent.py."""

    def __init__(self):
        super().__init__(
            agent_name="PeStudio_Static_Triage_Analyzer",
            system_prompt=(
                "Deterministic automation agent -- this system prompt is unused. "
                "See agents/file_analysis/pestudio_analysis.py."
            ),
            include_event_context=False,
        )

    async def process_task(self, staging_root: Path):
        reports = await _build_static_triage_reports(staging_root)

        anomalies_found = []
        for report, _fpath in reports:
            for indicator in report.indicators:
                anomalies_found.append({
                    "filepath": report.filepath,
                    "anomaly_type": indicator.get("type", "Static Indicator"),
                    "severity": indicator.get("severity", "Medium"),
                    "justification": indicator.get("detail", ""),
                    "recommended_action": "Escalate to Reverse Engineering & String Analyzer",
                })
            for cap in report.capa_capabilities:
                anomalies_found.append({
                    "filepath": report.filepath,
                    "anomaly_type": f"CAPA: {cap.capability}",
                    "severity": cap.confidence,
                    "justification": f"MITRE {cap.technique_id or '?'} ({cap.technique_name or cap.tactic or 'uncategorized'})",
                    "recommended_action": "Correlate against dynamic sandbox behavior",
                })

        yara_anomalies = _yara_scan_staging_root(staging_root)
        anomalies_found.extend(yara_anomalies)

        status = "Clean"
        if any(r.status == "Critical" for r, _ in reports) or any(a["severity"] == "Critical" for a in yara_anomalies):
            status = "Critical"
        elif any(r.status == "Suspicious" for r, _ in reports) or yara_anomalies:
            status = "Suspicious"

        deterministic_analysis = {
            "agent_name": self.agent_name,
            "status": status,
            "anomalies_found": anomalies_found,
            "summary": f"{len(reports)} binar{'y' if len(reports) == 1 else 'ies'} triaged (PE/ELF), "
                       f"{len(yara_anomalies)} YARA rule match(es).",
        }
        parsed_tool_data = {
            "staging_root": str(staging_root),
            "reports": [r.dict() for r, _ in reports],
        }
        response = await self.run_automated_with_hitl(
            parsed_tool_data=parsed_tool_data,
            deterministic_analysis=deterministic_analysis,
        )
        # Stashed for the Father Agent's conditional dynamic-analysis gate --
        # see file_analysis_master.py -- without re-triaging from scratch.
        response.ai_analysis["_static_reports"] = [
            {"report": r.dict(), "filepath": str(fpath)} for r, fpath in reports
        ]
        return response


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = StaticTriageAndCapabilityMapperAgent()
    asyncio.run(agent.process_task(staging_root))
