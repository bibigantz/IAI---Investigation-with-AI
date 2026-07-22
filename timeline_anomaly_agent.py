import asyncio
import sys
from pathlib import Path
from core_agents import BaseHITLAgent, locate_staging_directory

class TimelineAnomalyAgent(BaseHITLAgent):
    """
    Super Timeline Anomaly Detector Agent
    Developer Owner: [ Y ]
    
    Purpose: Evaluates disk activity timeline (e.g., Plaso log2timeline / psort output)
             to detect anti-forensics, time-stomping, file deletion bursts, and hidden data staging.
    """
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
        """Processes Timeline artifacts from the staging directory."""
        # Timeline data can reside under Logs or a dedicated Plaso/Timeline folder
        parsed_json_data = self.parse_category_artifacts(staging_root, "Logs")
        return await self.run_with_hitl(parsed_tool_data=parsed_json_data)


if __name__ == "__main__":
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    staging_root = locate_staging_directory(explicit_path=explicit_path)
    agent = TimelineAnomalyAgent()
    asyncio.run(agent.process_task(staging_root))
