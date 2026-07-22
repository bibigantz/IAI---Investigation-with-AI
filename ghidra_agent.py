import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class GhidraAgent(BaseHITLAgent):
    """
    File Analysis - Ghidra Reverse Engineering Agent
    Developer Owner: [ N ]
    
    Purpose: Interfaces with Ghidra MCP headless auto-analysis output to analyze decompiled
             C/C++ pseudo-code of high-entropy or critical functions, deciphering C2 logic,
             decryption routines, and anti-analysis mechanisms.
    """
    def __init__(self):
        super().__init__(
            agent_name="Ghidra_Reverse_Engineering_Agent",
            system_prompt=(
                "You are a Senior Reverse Engineer analyzing decompiled C pseudo-code produced by Ghidra auto-analysis. "
                "Dissect algorithmic logic, custom string decoding routines, dynamic API resolution (GetProcAddress / LoadLibrary), "
                "C2 communication protocol structure, anti-debugging / anti-VM tricks, and persistence payload dropping logic. "
                "Provide step-by-step technical explanations of function functionality."
            )
        )

    async def process_task(self, staging_root: Path):
        """Processes Ghidra decompilation artifacts from the staging directory."""
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = GhidraAgent()
    asyncio.run(agent.process_task(staging_root))
