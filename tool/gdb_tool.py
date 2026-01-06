# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A tool for LLM agents to interact within a GDB."""
import logging
import os
import subprocess as sp
import time

from experiment.benchmark import Benchmark
from results import RunResult
from tool.container_tool import ProjectContainerTool

logger = logging.getLogger(__name__)


class GDBTool(ProjectContainerTool):
    """A tool for LLM agents to interact within a GDB."""

    def __init__(
        self,
        benchmark: Benchmark,
        result: RunResult,
        name: str = "",
        project_name: str = "",
    ) -> None:
        super().__init__(benchmark, name, project_name)
        self.result = result

    def tutorial(self) -> str:
        """Constructs a tool guide tutorial for LLM agents."""
        return (
            self._get_tutorial_file_content("gdb_tool.txt")
            .replace(
                "{AFTIFACT_PATH}",
                f"/artifact/{os.path.basename(self.result.artifact_path)}",
            )
            .replace("{TARGET_NAME}", self.benchmark.target_name)
        )

    def execute_in_screen(self, gdb_command: str) -> sp.CompletedProcess:
        """Sends a command to the gdb_session screen and returns GDB output."""
        self.execute("screen -S gdb_session -X logfile flush 0")
        self.execute("truncate -s 0 /tmp/gdb_log.txt")

        safe_cmd = gdb_command.replace('"', '\\"') + "\r"
        self.execute(f'screen -S gdb_session -X stuff "{safe_cmd}"')

        time.sleep(1.0)
        self.execute("screen -S gdb_session -X logfile flush 0")
        return self.execute("cat /tmp/gdb_log.txt")
