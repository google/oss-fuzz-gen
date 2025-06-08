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
"""A tool for LLM agents to interact within a LLDB."""
import logging
import subprocess as sp
import time

from experiment.benchmark import Benchmark
from results import RunResult
from tool.container_tool import ProjectContainerTool

logger = logging.getLogger(__name__)


class LLDBTool(ProjectContainerTool):
    """A tool for LLM agents to interact within a LLDB."""

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
            self._get_tutorial_file_content("lldb_tool.txt")
            .replace("{AFTIFACT_NAME}", self.result.artifact_name)
            .replace("{TARGET_NAME}", self.benchmark.target_name)
        )

    def execute(self, command: str) -> sp.CompletedProcess:
        """Executes the |command| in the container and returns the output."""
        logger.debug("Executing command (%s) in %s: ", command, self.container_id)
        execute_command_in_container = [
            "docker",
            "exec",
            self.container_id,
            "/bin/bash",
            "-c",
            command,
        ]
        process = self._execute_command_in_container(execute_command_in_container)
        process.args = command
        return process

    def execute_in_screen(self, lldb_command: str) -> sp.CompletedProcess:
        """Sends a command to the lldb_session screen and returns LLDB output."""
        self.execute("screen -S lldb_session -X logfile flush 0")
        self.execute("truncate -s 0 /tmp/lldb_log.txt")

        safe_cmd = lldb_command.replace('"', '\\"') + "\r"
        self.execute(f'screen -S lldb_session -X stuff "{safe_cmd}"')

        time.sleep(1.0)
        self.execute("screen -S lldb_session -X logfile flush 0")
        return self.execute("cat /tmp/lldb_log.txt")
