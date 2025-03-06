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
import os
import subprocess as sp

from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from results import RunResult
from tool.container_tool import ProjectContainerTool

logger = logging.getLogger(__name__)


class LLDBTool(ProjectContainerTool):
  """A tool for LLM agents to interact within a LLDB."""

  def __init__(self,
               benchmark: Benchmark,
               project: str,
               result: RunResult,
               name: str = '') -> None:
    super().__init__(benchmark, name)
    self.project = project
    self.result = result
    self.image_name = self._prepare_project_image()
    self.container_id = self._start_docker_container()

  def _prepare_project_image(self) -> str:
    """Prepares the project's OSS-Fuzz docker image and returns the image name.
    """
    image_name = f'gcr.io/oss-fuzz/{self.project}-lldb'
    # TODO(maoyi): implement image cache
    if oss_fuzz_checkout.image_exists_locally(image_name, self.project):
      logger.info('Using existing project image for %s', self.project)
      return image_name
    logger.info('Unable to find existing project image for %s', self.project)
    command = [
        'docker', 'build', '-t', image_name,
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects', self.project)
    ]
    try:
      sp.run(command, cwd=oss_fuzz_checkout.OSS_FUZZ_DIR, check=True)
      logger.info('Successfully build project image for %s', self.project)
      return image_name
    except sp.CalledProcessError:
      logger.info('Failed to build image for %s', self.project)
      return ''

  def tutorial(self) -> str:
    """Constructs a tool guide tutorial for LLM agents."""
    return self._get_tutorial_file_content('lldb_tool.txt')\
      .replace('{AFTIFACT_NAME}', self.result.artifact_name)

  def execute(self, command: str) -> sp.CompletedProcess:
    """Executes the |command| in the container and returns the output."""
    logger.debug('Executing command (%s) in %s: ', command, self.container_id)
    execute_command_in_container = [
        'docker', 'exec', self.container_id, '/bin/bash', '-c', command
    ]
    process = self._execute_command_in_container(execute_command_in_container)
    process.args = command
    return process
