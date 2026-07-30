import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class NetworkAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Network_Socket_Correlator",
            system_prompt=(
                "You are a Network Memory Analyst examining active and closed sockets extracted via Volatility netscan. "
                "Correlate process IDs (PIDs) holding open network connections against expected process behavior. "
                "Flag non-standard processes opening outbound connections (e.g. notepad.exe or lsass.exe connecting to remote IPs), "
                "connections to suspicious high-numbered ports, C2 communication channels, and listening sockets on non-standard ports."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = NetworkAgent()
    asyncio.run(agent.process_task(staging_root))
