import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from Registry import Registry

from core.base_agent import BaseHITLAgent
from core.models import RegistryPersistenceEntry
from core.utils import locate_staging_directory

# (relative key path from hive root, persistence category, MITRE technique)
_RUN_KEY_PATHS: List[Tuple[str, str, str]] = [
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run Key", "T1547.001"),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce Key", "T1547.001"),
    ("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run Key (Wow6432Node)", "T1547.001"),
    ("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce Key (Wow6432Node)", "T1547.001"),
]

_WINLOGON_PATH = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
_WINLOGON_VALUES = ["Shell", "Userinit", "Notify"]

_APPINIT_PATHS = [
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
]

_SERVICES_PATH = "Services"  # relative to the resolved current ControlSet


def _detect_hive_type(filename: str) -> str:
    upper = filename.upper()
    if "SYSTEM" in upper:
        return "SYSTEM"
    if "SOFTWARE" in upper:
        return "SOFTWARE"
    if "NTUSER" in upper:
        return "NTUSER"
    return "UNKNOWN"


def _navigate(root, relative_path: str):
    """Walk a backslash-delimited key path from a given root key.
    Raises Registry.RegistryKeyNotFoundException if any segment is missing."""
    key = root
    for part in relative_path.split("\\"):
        if part:
            key = key.subkey(part)
    return key


def _value_to_str(value) -> Optional[str]:
    try:
        data = value.value()
        if isinstance(data, (bytes, bytearray)):
            return data.hex()
        if isinstance(data, list):
            return " | ".join(str(x) for x in data)
        return str(data)
    except Exception:
        return None


def extract_run_keys(root, hive_file: str, hive_type: str) -> List[RegistryPersistenceEntry]:
    entries: List[RegistryPersistenceEntry] = []
    for key_path, category, technique in _RUN_KEY_PATHS:
        try:
            key = _navigate(root, key_path)
        except Registry.RegistryKeyNotFoundException:
            continue
        for value in key.values():
            entries.append(RegistryPersistenceEntry(
                hive_file=hive_file, hive_type=hive_type, key_path=key_path,
                value_name=value.name(), value_type=str(value.value_type_str()),
                value_data=_value_to_str(value),
                persistence_category=category, mitre_technique=technique,
            ))
    return entries


def extract_winlogon(root, hive_file: str, hive_type: str) -> List[RegistryPersistenceEntry]:
    entries: List[RegistryPersistenceEntry] = []
    try:
        key = _navigate(root, _WINLOGON_PATH)
    except Registry.RegistryKeyNotFoundException:
        return entries
    for value_name in _WINLOGON_VALUES:
        try:
            value = key.value(value_name)
        except Registry.RegistryValueNotFoundException:
            continue
        entries.append(RegistryPersistenceEntry(
            hive_file=hive_file, hive_type=hive_type, key_path=_WINLOGON_PATH,
            value_name=value.name(), value_type=str(value.value_type_str()),
            value_data=_value_to_str(value),
            persistence_category="Winlogon Shell/Userinit", mitre_technique="T1547.004",
        ))
    return entries


def extract_appinit_dlls(root, hive_file: str, hive_type: str) -> List[RegistryPersistenceEntry]:
    entries: List[RegistryPersistenceEntry] = []
    for key_path in _APPINIT_PATHS:
        try:
            key = _navigate(root, key_path)
            value = key.value("AppInit_DLLs")
        except (Registry.RegistryKeyNotFoundException, Registry.RegistryValueNotFoundException):
            continue
        data = _value_to_str(value)
        if not data:
            continue
        entries.append(RegistryPersistenceEntry(
            hive_file=hive_file, hive_type=hive_type, key_path=key_path,
            value_name="AppInit_DLLs", value_type=str(value.value_type_str()),
            value_data=data,
            persistence_category="AppInit_DLLs", mitre_technique="T1546.010",
        ))
    return entries


def extract_services(root, hive_file: str, hive_type: str) -> Tuple[List[RegistryPersistenceEntry], Optional[str]]:
    """SYSTEM-hive only. CurrentControlSet is a live-registry symlink that does
    not exist as a real key inside an offline hive file -- the active control
    set number must be resolved via Select\\Current first."""
    entries: List[RegistryPersistenceEntry] = []
    try:
        select_key = root.subkey("Select")
        current = select_key.value("Current").value()
    except (Registry.RegistryKeyNotFoundException, Registry.RegistryValueNotFoundException) as e:
        return entries, f"Could not resolve current ControlSet: {e}"

    control_set_name = f"ControlSet{int(current):03d}"
    try:
        services_key = root.subkey(control_set_name).subkey(_SERVICES_PATH)
    except Registry.RegistryKeyNotFoundException as e:
        return entries, f"{control_set_name}\\Services not found: {e}"

    key_path = f"{control_set_name}\\{_SERVICES_PATH}"
    for svc_key in services_key.subkeys():
        try:
            image_path = _value_to_str(svc_key.value("ImagePath"))
        except Registry.RegistryValueNotFoundException:
            image_path = None
        if image_path is None:
            continue  # driver/service stub with no executable path -- nothing to evaluate
        try:
            start_val = _value_to_str(svc_key.value("Start"))
        except Registry.RegistryValueNotFoundException:
            start_val = None
        entries.append(RegistryPersistenceEntry(
            hive_file=hive_file, hive_type=hive_type,
            key_path=f"{key_path}\\{svc_key.name()}",
            value_name="ImagePath", value_type="Service Definition",
            value_data=f"ImagePath={image_path} | Start={start_val}",
            persistence_category="Service ImagePath", mitre_technique="T1543.003",
        ))
    return entries, None


def mine_hive_file(hive_path: Path) -> Tuple[List[RegistryPersistenceEntry], Optional[str]]:
    hive_type = _detect_hive_type(hive_path.name)
    try:
        reg = Registry.Registry(str(hive_path))
        root = reg.root()
    except Exception as e:
        return [], f"Failed to open hive: {e}"

    entries: List[RegistryPersistenceEntry] = []
    entries.extend(extract_run_keys(root, hive_path.name, hive_type))
    entries.extend(extract_winlogon(root, hive_path.name, hive_type))
    entries.extend(extract_appinit_dlls(root, hive_path.name, hive_type))

    services_error = None
    if hive_type == "SYSTEM":
        service_entries, services_error = extract_services(root, hive_path.name, hive_type)
        entries.extend(service_entries)

    return entries, services_error


class RegistryMinerAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Registry_Hive_Miner",
            system_prompt=(
                "You are a Windows Registry Forensic Specialist. You are given a structured list of "
                "extracted persistence-relevant registry values pulled directly from the SYSTEM, SOFTWARE, "
                "and/or NTUSER hive files collected for this case: Run/RunOnce keys (HKLM and HKCU, "
                "including the Wow6432Node 32-bit view), Winlogon Shell/Userinit/Notify, AppInit_DLLs, and "
                "Windows service ImagePath/Start values from the hive's resolved current ControlSet. "
                "Each entry already carries its MITRE ATT&CK technique tag. "
                "Evaluate whether each value_data path points to a user-writable location (Temp, "
                "AppData, ProgramData, Downloads) rather than C:\\Windows or C:\\Program Files, whether an "
                "AppInit_DLLs entry references anything at all (any non-empty value here is unusual on a "
                "modern system), and whether a service's ImagePath is unquoted with embedded spaces "
                "(unquoted service path vulnerability) or points outside expected system directories. "
                "Cross-reference paths against common benign software naming; flag anything else as "
                "suspicious with its MITRE technique cited in your justification."
            )
        )

    def _mine_registry_category(self, staging_root: Path) -> Tuple[List[RegistryPersistenceEntry], List[str]]:
        raw_dir = staging_root / "Registry" / "raw"
        all_entries: List[RegistryPersistenceEntry] = []
        issues: List[str] = []

        if not raw_dir.exists():
            issues.append(f"No Registry/raw/ folder present under {staging_root / 'Registry'}")
            return all_entries, issues

        hive_files = [p for p in raw_dir.iterdir() if p.is_file()]
        if not hive_files:
            issues.append("Registry/raw/ exists but contains no hive files.")
            return all_entries, issues

        for hive_path in hive_files:
            entries, error = mine_hive_file(hive_path)
            all_entries.extend(entries)
            if error:
                issues.append(f"{hive_path.name}: {error}")

        return all_entries, issues

    async def process_task(self, staging_root: Path):
        entries, issues = self._mine_registry_category(staging_root)

        meta_dir = staging_root / "Registry" / "metadata"
        if entries:
            meta_dir.mkdir(parents=True, exist_ok=True)
            self.write_records_csv(entries, meta_dir / "registry_persistence_entries.csv")

        existing_metadata = self._read_metadata_dir(meta_dir)

        payload: Dict[str, Any] = {
            "category": "Registry",
            "category_path": str(staging_root / "Registry"),
            "persistence_entry_count": len(entries),
            "persistence_entries": [e.dict() for e in entries],
            "extraction_issues": issues,
            "metadata": existing_metadata,
        }

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = RegistryMinerAgent()
    asyncio.run(agent.process_task(staging_root))
