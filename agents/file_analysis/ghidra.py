import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class GhidraAgent(BaseHITLAgent):
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
        parsed_json_data = self.parse_category_artifacts(staging_root, "ProgramDataList")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = GhidraAgent()
    asyncio.run(agent.process_task(staging_root))
