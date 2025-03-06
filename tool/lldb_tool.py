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
from tool.base_tool import BaseTool

logger = logging.getLogger(__name__)


class LLDBTool(BaseTool):
  """A tool for LLM agents to interact within a LLDB."""

  def __init__(self, benchmark: Benchmark, name: str, project: str,
               result: RunResult) -> None:
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

  def _execute_command(self,
                       command: list[str],
                       in_container: bool = False) -> sp.CompletedProcess:
    """Executes the |command| in subprocess and log output."""
    result = sp.run(command,
                    stdout=sp.PIPE,
                    stderr=sp.PIPE,
                    check=False,
                    text=True)

    if in_container:
      logger.debug(
          'Executing command (%s) in container %s: Return code %d. STDOUT: %s, '
          'STDERR: %s', command, self.container_id, result.returncode,
          result.stdout, result.stderr)
    else:
      logger.debug(
          'Executing command (%s): Return code %d. STDOUT: %s, '
          'STDERR: %s', command, result.returncode, result.stdout,
          result.stderr)
    return result

  def _start_docker_container(self) -> str:
    """Runs the project's OSS-Fuzz image as a background container and returns
    the container ID."""
    run_container_command = [
        'docker', 'run', '-d', '-t', '--privileged', '--shm-size=2g',
        '--entrypoint=/bin/bash', '--platform', 'linux/amd64', '-e',
        'FUZZING_ENGINE=libfuzzer', '-e', 'SANITIZER=address', '-e',
        'ARCHITECTURE=x86_64', '-e', f'PROJECT_NAME={self.project}', '-e',
        f'FUZZING_LANGUAGE={self.benchmark.language}', '-v',
        f'{self.result.artifact_path}:/artifact/{self.result.artifact_name}',
        self.image_name
    ]
    result = self._execute_command(run_container_command)
    container_id = result.stdout.strip()
    return container_id

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
    process = self._execute_command(execute_command_in_container, True)
    process.args = command
    return process

  def terminate(self) -> bool:
    """Terminates the container."""
    terminate_container_command = ['docker', 'stop', self.container_id]
    result = self._execute_command(terminate_container_command)
    return result.returncode == 0
