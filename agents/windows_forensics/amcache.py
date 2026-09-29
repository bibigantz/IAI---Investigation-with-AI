import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory
from .execution_artifacts_common import parse_amcacheparser_csv


class AmcacheAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Amcache_Analyzer",
            system_prompt=(
                "You are a Forensic Investigator inspecting Windows Amcache.hve metadata (AmcacheParser output). "
                "You are given a structured list of file-entry records (full path, name, SHA1, size, whether "
                "Microsoft flags it as an OS component, compile/link date, and last-write timestamp). Each record "
                "has ALREADY been checked in code for exact-name/typosquat matches against well-known system "
                "binaries, carried as is_masquerade_suspect/masquerade_reason -- treat true as a strong signal. "
                "Independently flag: executables in Temp/AppData/Downloads/ProgramData staging directories, "
                "is_os_component=false binaries claiming a Microsoft ProductName (a real Windows component would "
                "be flagged true), and a compile/link date that is implausibly recent relative to the file's "
                "last-write timestamp (fresh compilation immediately before deployment is a common malware tell). "
                "AmcacheParser CSVs that are not file-entry tables (ProgramEntries, ShortCuts, DriverBinaries) are "
                "filtered out upstream -- you will only ever see actual file execution/presence evidence here."
            )
        )

    async def process_task(self, staging_root: Path):
        meta_dir = staging_root / "Amcache" / "metadata"
        csvs = sorted(meta_dir.glob("*.csv")) if meta_dir.exists() else []

        artifacts = []
        issues = []
        for csv_path in csvs:
            parsed, err = parse_amcacheparser_csv(csv_path)
            artifacts.extend(parsed)
            if err:
                issues.append(f"{csv_path.name}: {err}")

        existing_metadata = self._read_metadata_dir(meta_dir) if meta_dir.exists() else []
        if artifacts:
            self.write_records_csv(artifacts, meta_dir / "Amcache_execution_artifacts.csv")

        payload: Dict[str, Any] = {
            "category": "Amcache",
            "artifact_count": len(artifacts),
            "artifacts": [a.dict() for a in artifacts],
            "parsing_issues": issues,
            "metadata": existing_metadata,
        }
        if not csvs:
            payload["note"] = "No AmcacheParser CSV output found under Amcache/metadata/."

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = AmcacheAgent()
    asyncio.run(agent.process_task(staging_root))
