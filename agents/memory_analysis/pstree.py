import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class PsTreeAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="PsTree_Process_Mapper",
            system_prompt=(
                "You are a Volatile Memory Forensic Expert analyzing process listings from Volatility 3. "
                "Compare output between pslist, pstree, and psxview plugins to flag DKOM (Direct Kernel Object Manipulation), "
                "hidden or unlinked processes (e.g. False in pslist but True in psxview/ethread), "
                "parent-child relationship anomalies (e.g., cmd.exe spawned by svchost.exe without services.exe), "
                "and suspicious process names executing from non-standard memory spaces."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = PsTreeAgent()
    asyncio.run(agent.process_task(staging_root))
