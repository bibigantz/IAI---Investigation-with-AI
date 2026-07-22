import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class PeStudioAnalysisAgent(BaseHITLAgent):
    """
    File Analysis - Static Triage & Capability Mapper Agent (PeStudio / CAPA)
    Developer Owner: [ N ]
    
    Purpose: Rapid static triage of suspicious PE binaries using PE header metadata,
             imports, exports, section entropy, SSDEEP/ImpHash, and CAPA MITRE ATT&CK capability mappings.
    """
    def __init__(self):
        super().__init__(
            agent_name="PeStudio_Static_Triage_Analyzer",
            system_prompt=(
                "You are a Malware Analyst performing static triage on executable binaries. "
                "You are given static metadata, PE headers, import/export tables, section entropy, "
                "and CAPA capability mappings. Identify suspicious characteristics such as high-entropy sections "
                "(packing/encryption), suspicious API imports (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), "
                "missing compilation timestamps, and MITRE ATT&CK capability matches."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes File Analysis artifacts from the staging directory."""
        # Reads staged binary metadata or extracted parser JSON
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = PeStudioAnalysisAgent()
    asyncio.run(agent.process_task(staging_root))
