import asyncio
import sys
from pathlib import Path
from core.base_agent import BaseHITLAgent
from core.utils import locate_staging_directory


class TimelineAnomalyAgent(BaseHITLAgent):
    def __init__(self):
        super().__init__(
            agent_name="Timeline_Anomaly_Detector",
            system_prompt=(
                "You are a Forensic Timeline Analyst inspecting a master super-timeline of filesystem and OS events. "
                "Analyze time clusters, MACB (Modified, Accessed, Created, Born) timestamp anomalies, "
                "evidence of time-stomping (e.g. file creation date prior to system installation), "
                "mass file renaming or deletion (ransomware indicator), and staging activity prior to exfiltration."
            )
        )

    async def process_task(self, staging_root: Path):
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = TimelineAnomalyAgent()
    asyncio.run(agent.process_task(staging_root))
