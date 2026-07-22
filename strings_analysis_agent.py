import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class StringsAnalysisAgent(BaseHITLAgent):
    """
    File Analysis - Strings Analyzer Agent
    Developer Owner: [ N ]
    
    Purpose: Extracts and analyzes ASCII/Unicode strings, hardcoded IP addresses, URLs,
             registry key paths, User-Agents, base64 payloads, and error strings from suspicious binaries.
    """
    def __init__(self):
        super().__init__(
            agent_name="Strings_Analyzer",
            system_prompt=(
                "You are a Reverse Engineer examining extracted string artifacts from a target binary. "
                "Analyze ASCII and Unicode strings for Indicators of Compromise (IOCs): C2 IP addresses, domains, "
                "URL paths, hardcoded encryption keys, user-agent strings, suspicious registry locations, "
                "PowerShell/cmd.exe execution strings, and base64/hex obfuscated data."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes File Analysis artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = StringsAnalysisAgent()
    asyncio.run(agent.process_task(staging_root))
