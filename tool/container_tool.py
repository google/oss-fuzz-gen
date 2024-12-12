"""A tool for LLM agents to interact within a project's docker container."""
import logging
import subprocess as sp
from typing import Any

from vertexai.preview.generative_models import FunctionDeclaration

from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from tool.base_tool import BaseTool

logger = logging.getLogger(__name__)


class ProjectContainerTool(BaseTool):
  """A tool for LLM agents to interact within a project's docker container."""

  def __init__(self, benchmark: Benchmark, name: str = '') -> None:
    super().__init__(benchmark, name)
    self.image_name = self._prepare_project_image()
    self.container_id = self._start_docker_container()

  def declarations(self) -> list[Any]:
    """Declares the function call APIs for LLM interaction."""
    return [
        FunctionDeclaration(
            name='bash',
            description=('Inspects source code, environment variables, and file'
                         ' systems with bash commands to collect information '
                         'for fuzz target and build script generation.'),
            parameters={
                'type': 'object',
                'properties': {
                    'reason': {
                        'type':
                            'string',
                        'description': (
                            'The reason to execute the bash command. E.g., '
                            'Inspect and learn from all existing human written '
                            'fuzz targets as examples.'),
                    },
                    'command': {
                        'type':
                            'string',
                        'description':
                            ('The bash command to execute. E.g., grep -rlZ '
                             '"LLVMFuzzerTestOneInput(" "$(dirname '
                             f'{self.benchmark.target_path})" | xargs -0 cat'),
                    },
                    # TODO(dongge): Another parameter to judge if the previous
                    # bash command is useful? We can save the useful commands
                    # and outputs to speed up future generations.
                },
                'required': ['reason', 'command'],
            },
        ),
        FunctionDeclaration(
            name='compile',
            description=('Submits the **entire** source code of the fuzz target'
                         ' and build script for compilation and fuzzing. Use '
                         'this function call only if you have thorougly studied'
                         ' the function and the project under test.'),
            parameters={
                'type': 'object',
                'properties': {
                    'summary': {
                        'type':
                            'string',
                        'description':
                            ('The important notes, insights, and lessons learnt'
                             ' above when generating the fuzz target and the '
                             'build script.'),
                    },
                    'fuzz_target': {
                        'type':
                            'string',
                        'description':
                            ('The **entire** fuzz target immediately ready for '
                             'compilation and fuzzing.'),
                    },
                    'build_script': {
                        'type':
                            'string',
                        'description': (
                            'The **entire** build script immediately ready for '
                            'compilation and fuzzing.'),
                    },
                    'referenced': {
                        'type':
                            'boolean',
                        'description': (
                            'Pass True if the function-under-test is invoked by'
                            ' the fuzz_target; Otherwise return False.'),
                    },
                },
                'required': ['summary', 'fuzz_target', 'referenced'],
            },
        ),
    ]

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

  def _execute_command_in_container(self,
                                    command: list[str]) -> sp.CompletedProcess:
    """Executes the |command| in subprocess and log output."""
    try:
      result = sp.run(command,
                      stdout=sp.PIPE,
                      stderr=sp.PIPE,
                      check=False,
                      text=True,
                      encoding='utf-8',
                      errors='ignore')

      logger.debug(
          'Executing command (%s) in container %s: Return code %d. STDOUT: %s, '
          'STDERR: %s', command, self.container_id, result.returncode,
          result.stdout, result.stderr)
      return result
    except Exception as e:
      logger.error(
          'Executing command (%s) in container failed with Exception: %s',
          command, e)
      return sp.CompletedProcess(command, returncode=1, stdout='', stderr='')

  def _execute_command(self, command: list[str]) -> sp.CompletedProcess:
    """Executes the |command| in subprocess and log output."""
    try:
      result = sp.run(command,
                      stdout=sp.PIPE,
                      stderr=sp.PIPE,
                      check=False,
                      text=True,
                      encoding='utf-8',
                      errors='ignore')

      logger.debug(
          'Executing command (%s): Return code %d. STDOUT: %s, STDERR: %s',
          command, result.returncode, result.stdout, result.stderr)
      return result
    except Exception as e:
      logger.error('Executing command (%s) failed with Exception: %s', command,
                   e)
      return sp.CompletedProcess(command, returncode=1, stdout='', stderr='')

  def _start_docker_container(self) -> str:
    """Runs the project's OSS-Fuzz image as a background container and returns
    the container ID."""
    run_container_command = [
        'docker', 'run', '-d', '-t', '--entrypoint=/bin/bash', '-e',
        f'FUZZING_LANGUAGE={self.benchmark.language}', self.image_name
    ]
    result = self._execute_command(run_container_command)
    if result.returncode:
      logger.error('Failed to start container of image: %s', self.image_name)
    container_id = result.stdout.strip()
    return container_id

  def execute(self, command: str) -> sp.CompletedProcess:
    """Executes the |command| in the container and returns the output."""
    logger.debug('Executing command (%s) in %s: ', command, self.container_id)
    execute_command_in_container = [
        'docker', 'exec', self.container_id, '/bin/bash', '-c', command
    ]
    process = self._execute_command_in_container(execute_command_in_container)
    process.args = command
    return process

  def compile(self, extra_commands: str = '') -> sp.CompletedProcess:
    """Compiles the fuzz target."""
    command = 'compile > /dev/null' + extra_commands
    return self.execute(command)

  def terminate(self) -> bool:
    """Terminates the container."""
    terminate_container_command = ['docker', 'stop', self.container_id]
    result = self._execute_command(terminate_container_command)
    return result.returncode == 0
