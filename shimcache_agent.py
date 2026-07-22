import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class ShimcacheAgent(BaseHITLAgent):
    """
    Execution Artifacts Analyzer - Shimcache / AppCompatCache Tool Agent
    Developer Owner: [ G ]
    
    Purpose: Parses AppCompatCache / Shimcache entries (parsed by AppCompatCacheParser.exe into CSV/JSON metadata)
             to identify historical file presence and execution indicators across Windows system boots.
    """
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
        """Processes Shimcache artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "Shimcache")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = ShimcacheAgent()
    asyncio.run(agent.process_task(staging_root))
