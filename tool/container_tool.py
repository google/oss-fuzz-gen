"""A tool for LLM agents to interact within a project's docker container."""
import logging
import subprocess as sp

from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from tool.base_tool import BaseTool

logger = logging.getLogger(__name__)


class ProjectContainerTool(BaseTool):
  """A tool for LLM agents to interact within a project's docker container."""

  def __init__(self, bechmark: Benchmark, name: str = '') -> None:
    super().__init__(name)
    self.benchmark = bechmark
    self.image_name = self._prepare_project_image()
    self.container_id = self._start_docker_container()

  def tutorial(self) -> str:
    """Constructs a tool guide tutorial for LLM agents."""
    return self._get_tutorial_file_content('container_tool.txt').replace(
        '{FUZZ_TARGET_PATH}', self.benchmark.target_path)

  def _prepare_project_image(self) -> str:
    """Prepares the project's OSS-Fuzz docker image and returns the image name.
    """
    image_name = oss_fuzz_checkout.prepare_project_image(self.benchmark.project)
    if image_name:
      return image_name
    raise Exception(f'Failed to build image for {self.benchmark.project}')

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
        'docker', 'run', '-d', '-t', '--entrypoint=/bin/bash', '-e',
        f'FUZZING_LANGUAGE={self.benchmark.language}', self.image_name
    ]
    result = self._execute_command(run_container_command)
    container_id = result.stdout.strip()
    return container_id

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
