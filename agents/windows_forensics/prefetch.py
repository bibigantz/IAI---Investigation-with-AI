import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory
from .execution_artifacts_common import parse_pecmd_csv


class PrefetchAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Prefetch_Analyzer",
            system_prompt=(
                "You are a Windows Forensics expert specializing in Execution Artifacts and Prefetch analysis. "
                "You are given a structured list of parsed Prefetch (.pf) execution records (executable name, "
                "resolved full path from FilesLoaded, run count, last-execution timestamp, volume serial, hash) "
                "from PECmd.exe. Each record has ALREADY been checked in code for two specific patterns and "
                "carries the result as is_masquerade_suspect/masquerade_reason: (a) exact-name matches of "
                "well-known system binaries (svchost.exe, lsass.exe, cmd.exe, rundll32.exe, certutil.exe, ...) "
                "running outside their canonical System32/SysWOW64 directory, and (b) names 1-2 character edits "
                "away from a known system binary (svch0st.exe, lsas.exe, scvhost.exe -- typosquatting). "
                "Treat is_masquerade_suspect=true as a strong signal and assess its severity; also independently "
                "evaluate every record for unusual execution frequency (a single-run binary in a staging path, "
                "or an implausibly high run count for a supposedly one-off tool) and volume-serial mismatches "
                "across entries that suggest execution from removable/staged media. "
                "Base every finding on the structured fields provided -- do not speculate beyond them."
            )
        )

    async def process_task(self, staging_root: Path):
        meta_dir = staging_root / "Prefetch" / "metadata"
        csvs = sorted(meta_dir.glob("*.csv")) if meta_dir.exists() else []

        artifacts = []
        issues = []
        for csv_path in csvs:
            parsed, err = parse_pecmd_csv(csv_path)
            artifacts.extend(parsed)
            if err:
                issues.append(f"{csv_path.name}: {err}")

        existing_metadata = self._read_metadata_dir(meta_dir) if meta_dir.exists() else []
        if artifacts:
            self.write_records_csv(artifacts, meta_dir / "Prefetch_execution_artifacts.csv")

        payload: Dict[str, Any] = {
            "category": "Prefetch",
            "artifact_count": len(artifacts),
            "artifacts": [a.dict() for a in artifacts],
            "parsing_issues": issues,
            "metadata": existing_metadata,
        }
        if not csvs:
            payload["note"] = "No PECmd CSV output found under Prefetch/metadata/."

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = PrefetchAgent()
    asyncio.run(agent.process_task(staging_root))
