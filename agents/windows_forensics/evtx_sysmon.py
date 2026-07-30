import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class EvtxSysmonAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="EVTX_Sysmon_Correlator",
            system_prompt=(
                "You are an Incident Responder specializing in Windows Event Log (EVTX) and Sysmon analysis. "
                "You are given structured JSON/CSV metadata extracted from EvtxECmd and system logs. "
                "Focus heavily on process creation events (Event ID 1), network connections (Event ID 3), "
                "service creation (Event ID 7045), and script block logging (Event ID 4104). "
                "Correlate events to identify attack chains: initial execution -> command & control (C2) -> lateral movement."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = EvtxSysmonAgent()
    asyncio.run(agent.process_task(staging_root))
