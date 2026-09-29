import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory
from .execution_artifacts_common import parse_appcompatcache_csv


class ShimcacheAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Shimcache_Analyzer",
            system_prompt=(
                "You are a Forensic Investigator specializing in Application Compatibility Cache (Shimcache). "
                "You are given a structured list of parsed AppCompatCacheParser entries (full path, executable "
                "name, last-modified timestamp, cache position, and the raw 'Executed' flag). IMPORTANT caveat "
                "you must factor into your confidence: the 'Executed' flag is a well-known unreliable indicator "
                "on several Windows versions -- presence in the Shimcache means the binary was evaluated for "
                "compatibility (e.g. on file access or execution), and on older OS builds the flag itself may be "
                "absent entirely. Treat cache PRESENCE plus PATH as your primary signal, and 'Executed' as "
                "corroborating, not conclusive. Each record has already been checked in code for system-binary "
                "masquerading/typosquatting (is_masquerade_suspect/masquerade_reason) -- treat true as a strong "
                "signal. Independently flag payloads cached from Temp/Downloads/AppData/staging paths, and use "
                "cache_entry_position and last_execution_utc together to reason about relative ordering of "
                "execution across entries."
            )
        )

    async def process_task(self, staging_root: Path):
        meta_dir = staging_root / "Registry" / "metadata"
        csvs = sorted(meta_dir.glob("*.csv")) if meta_dir.exists() else []

        artifacts = []
        issues = []
        for csv_path in csvs:
            parsed, err = parse_appcompatcache_csv(csv_path)
            artifacts.extend(parsed)
            if err:
                issues.append(f"{csv_path.name}: {err}")

        existing_metadata = self._read_metadata_dir(meta_dir) if meta_dir.exists() else []
        if artifacts:
            self.write_records_csv(artifacts, meta_dir / "Shimcache_execution_artifacts.csv")

        payload: Dict[str, Any] = {
            "category": "Registry",
            "artifact_count": len(artifacts),
            "artifacts": [a.dict() for a in artifacts],
            "parsing_issues": issues,
            "metadata": existing_metadata,
        }
        if not csvs:
            payload["note"] = "No AppCompatCacheParser CSV output found under Registry/metadata/."

        parsed_json_data = self._truncate_payload(json.dumps(payload, default=str))
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = ShimcacheAgent()
    asyncio.run(agent.process_task(staging_root))
