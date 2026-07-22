import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class AmcacheAgent(BaseHITLAgent):
    """
    Execution Artifacts Analyzer - Amcache Tool Agent
    Developer Owner: [ G ]
    
    Purpose: Parses Amcache.hve (parsed by AmcacheParser.exe into CSV/JSON metadata)
             to extract SHA1 file hashes, execution paths, compilation timestamps, and installation data.
    """
    def __init__(self):
        super().__init__(
            agent_name="Amcache_Analyzer",
            system_prompt=(
                "You are a Forensic Investigator inspecting Windows Amcache.hve metadata (AmcacheParser output). "
                "Evaluate file execution evidence, SHA1 cryptographic hashes, full file paths, PE header timestamps, "
                "and publisher details. Flag unlinked or unregistered binaries, executables in temporary or staging "
                "directories, binaries lacking digital signatures, and known malware hashes or compilation time anomalies."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes Amcache artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "Amcache")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = AmcacheAgent()
    asyncio.run(agent.process_task(staging_root))
