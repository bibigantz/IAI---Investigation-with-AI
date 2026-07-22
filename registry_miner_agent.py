import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class RegistryMinerAgent(BaseHITLAgent):
    """
    Registry Hive Miner Agent
    Developer Owner: [ Y ]
    
    Purpose: Extracts SYSTEM, SOFTWARE, SAM, and NTUSER.DAT hives to detect persistence,
             user account modifications, autoruns, and system configuration tampering (parsed via RegRipper/RECmd).
    """
    def __init__(self):
        super().__init__(
            agent_name="Registry_Hive_Miner",
            system_prompt=(
                "You are a Windows Registry Forensic Specialist analyzing parsed hive key metadata (from RegRipper/RECmd). "
                "Evaluate Windows Run/RunOnce keys, UserInit, Shell modifications, Winlogon overrides, USB storage history, "
                "and service configurations. "
                "Flag paths pointing to user-writable folders, suspicious environment variable modifications, "
                "and persistence mechanisms matching MITRE ATT&CK techniques."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes Registry artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "Registry")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = RegistryMinerAgent()
    asyncio.run(agent.process_task(staging_root))
