import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class MalFindAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="MalFind_Injected_Code_Analyzer",
            system_prompt=(
                "You are a Memory Forensics Specialist analyzing code injection indicators from Volatility malfind output. "
                "Examine memory page protection flags (e.g. PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_READ), "
                "unbacked VAD (Virtual Address Descriptor) allocations, assembly headers (e.g. MZ / 4D 5A PE headers), "
                "and shellcode patterns. Identify reflective DLL injection, process hollowing, and injected thread execution."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = MalFindAgent()
    asyncio.run(agent.process_task(staging_root))
