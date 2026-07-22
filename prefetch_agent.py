import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class PrefetchAgent(BaseHITLAgent):
    """
    Execution Artifacts Analyzer - Prefetch Tool Agent
    Developer Owner: [ G ]
    
    Purpose: Parses Windows Prefetch files (parsed by PECmd.exe into CSV/JSON metadata)
             to answer what executed, when, execution frequency, and from where.
    """
    def __init__(self):
        super().__init__(
            agent_name="Prefetch_Analyzer",
            system_prompt=(
                "You are a Windows Forensics expert specializing in Execution Artifacts and Prefetch analysis. "
                "You are provided with raw inventory and parsed CSV metadata from PECmd.exe for Prefetch files (.pf). "
                "Analyze execution counts, last run timestamps, volume information, and loaded DLLs. "
                "Flag anomalies such as processes executing from unusual/user paths (e.g. Temp, AppData, Downloads), "
                "masquerading binaries (e.g. svchost.exe running outside System32), or suspicious execution frequency."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes Prefetch artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "Prefetch")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = PrefetchAgent()
    asyncio.run(agent.process_task(staging_root))
