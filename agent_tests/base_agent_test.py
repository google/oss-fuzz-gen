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
"""Base class for agent tests."""
import re

import logger


class BaseAgentTest:
    """Base class for agent tests, providing common setup and utility methods."""

    def __init__(self, args, trial):
        self.args = args
        self.trial = trial

    def _parse_tag(self, response: str, tag: str) -> str:
        """Parses the XML-style tags from LLM response."""
        match = re.search(rf"<{tag}>(.*?)</{tag}>", response, re.DOTALL)
        return match.group(1).strip() if match else ""

    def write_requirements_to_file(self, args, requirements: str) -> str:
        """Write the requirements to a file."""
        if not requirements:
            logger.warning("No requirements to write to file.", trial=self.trial)
            return ""

        requirement_path = args.work_dirs.requirements_file_path(self.trial)

        with open(requirement_path, "w") as f:
            f.write(requirements)

        logger.info("Requirements written to %s", requirement_path, trial=self.trial)

        return requirement_path

    def setup_initial_result_list(self, benchmark, prompt):
        """Sets up the initial result list for the agent test."""
        # Load the benchmark and prompt file
        raise NotImplementedError(
            "This method should be implemented in subclasses to set up the initial result list."
        )
