import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class ShimcacheAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Shimcache_Analyzer",
            system_prompt=(
                "You are a Forensic Investigator specializing in Application Compatibility Cache (Shimcache). "
                "Review parsed Shimcache entries (from AppCompatCacheParser). Track executed binary paths, "
                "modification timestamps, and order of execution. Identify malicious payloads executed from non-standard "
                "folders, temporary staging locations, or masquerading system paths."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Registry")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = ShimcacheAgent()
    asyncio.run(agent.process_task(staging_root))
