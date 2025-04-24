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
"""LLM Build Script Agent"""

import argparse
import os
import re
import subprocess
import time
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from experimental.build_generator import file_utils, templates
from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.base_tool import BaseTool
from tool.container_tool import ProjectContainerTool

MAX_PROMPT_LENGTH = 20000
SAMPLE_HEADERS_COUNT = 30
MAX_DISCOVERY_ROUND = 100


class BuildScriptAgent(BaseAgent):
  """Base class for buidl script agent."""

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               github_url: str,
               language: str,
               tools: Optional[list[BaseTool]] = None,
               name: str = ''):
    super().__init__(trial, llm, args, tools, name)
    self.github_url = github_url
    self.language = language
    self.build_files = {}
    self.last_status = False
    self.last_result = ''
    self.target_files = {}
    self.discovery_stage = False

    # Get sample fuzzing harness
    _, _, self.harness_path, self.harness_code = (
        file_utils.get_language_defaults(self.language))

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the tag from LLM response."""
    patterns = [rf'<{tag}>(.*?)</{tag}>', rf'```{tag}(.*?)```']

    # Matches both xml and code style tags
    for pattern in patterns:
      match = re.search(pattern, response, re.DOTALL)
      if match:
        return match.group(1).strip()

    return ''

  def _parse_tags(self, response: str, tag: str) -> list[str]:
    """Parses the tags from LLM response."""
    patterns = [rf'<{tag}>(.*?)</{tag}>', rf'```{tag}(.*?)```']
    found_matches = []

    # Matches both xml and code style tags
    for pattern in patterns:
      matches = re.findall(pattern, response, re.DOTALL)
      found_matches.extend([content.strip() for content in matches])

    return found_matches

  def _container_handle_bash_commands(self, response: str, tool: BaseTool,
                                      prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    # Initialise variables
    prompt_text = ''
    success = False

    # Retrieve data from response
    harness = self._parse_tag(response, 'fuzzer')
    build_script = '\n'.join(self._parse_tags(response, 'bash'))
    commands = '; '.join(self._parse_tags(response, 'command'))

    if build_script:
      self.discovery_stage = False

      # Update fuzzing harness
      if harness:
        self.harness_code = harness
      if isinstance(tool, ProjectContainerTool):
        tool.write_to_file(self.harness_code, self.harness_path)

      # Update build script
      if build_script:
        # Add set -e to ensure docker image failing is reflected.
        build_script = build_script.replace('#!/bin/bash', '')
        build_script = f'#!/bin/bash\nset -e\n{build_script}'

        # Update build script
        if isinstance(tool, ProjectContainerTool):
          tool.write_to_file(build_script, '/src/build.sh')

          # Test and parse result
          result = tool.execute('compile')
          format_result = self._format_bash_execution_result(
              result, previous_prompt=prompt)
          prompt_text = self._parse_tag(format_result, 'stderr') + '\n'
          if result.returncode == 0:
            success = True

    elif commands:
      # Execute the command directly, then return the formatted result
      self.discovery_stage = True
      result = tool.execute(commands)
      prompt_text = self._format_bash_execution_result(result,
                                                       previous_prompt=prompt)

      if result.returncode == 0:
        success = True

    self.last_status = success
    self.last_result = prompt_text

    return prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   build_result: BuildResult,
                                   prompt: Prompt) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new build script from LLM."""
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=build_result.trial)

    # Execution fail
    if not self.last_status:
      retry = templates.LLM_RETRY.replace('{BASH_RESULT}', self.last_result)

      # Refine prompt text to max prompt count and add to prompt
      length = min(len(retry), (MAX_PROMPT_LENGTH - len(prompt.gettext())))
      prompt.add_problem(retry[-length:])

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt

    # Execution success
    build_result.compiles = True
    build_result.fuzz_target_source = self.harness_code
    build_script_source = '\n'.join(self._parse_tags(response, 'bash'))
    if not build_script_source.startswith('#!'):
      build_script_source = templates.EMPTY_OSS_FUZZ_BUILD + build_script_source
    build_result.build_script_source = build_script_source

    return None

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    prompt = self.llm.prompt_type()(None)

    if response:
      prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                    prompt)

      # Check result and try building with the new builds script
      prompt = self._container_handle_conclusion(cur_round, response,
                                                 build_result, prompt)

      if prompt is None:
        return None

    if not response or not prompt or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, cur_round, response, prompt)

    return prompt

  def _prepare_repository(self) -> str:
    """Helper to prepare the repository for analysis."""
    target_path = os.path.join(self.args.work_dirs,
                               self.github_url.split('/')[-1])
    if not os.path.isdir(target_path):
      subprocess.check_call(
          f'git clone --recurse-submodules {self.github_url} {target_path}',
          shell=True)

    return os.path.abspath(target_path)

  def _discover_headers(self) -> list[str]:
    """Helper to discover some header files for inclusion."""
    # Prepare targert repository
    target_path = self._prepare_repository()

    headers = set()
    for root, _, files in os.walk(target_path):
      for file in files:
        if file.endswith((".h", ".hpp")):
          header_path = os.path.join(root, file)
          headers.add(header_path.replace(target_path, ''))

    return list(headers)

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    logger.info('Executing %s', self.name, trial=last_result.trial)
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    cur_round = 1
    dis_round = 1
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})

    prompt = self._initial_prompt(result_history)
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt:
        # Sleep for a minute to avoid over RPM
        time.sleep(60)

        response = self.chat_llm(cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=last_result.trial)
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)

        if self.discovery_stage:
          dis_round += 1
          if dis_round >= MAX_DISCOVERY_ROUND:
            break
        else:
          cur_round += 1
          if cur_round >= self.max_round:
            break
    finally:
      logger.info('Stopping and removing the inspect container %s',
                  self.inspect_tool.container_id,
                  trial=last_result.trial)
      self.inspect_tool.terminate()

    return build_result


class BuildSystemBuildScriptAgent(BuildScriptAgent):
  """Generate a working Dockerfile and build script from scratch
  with build system."""

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               github_url: str,
               language: str,
               tools: Optional[list[BaseTool]] = None,
               name: str = ''):
    super().__init__(trial, llm, args, github_url, language, tools, name)
    self.target_files = {
        'Makefile': [],
        'configure.ac': [],
        'Makefile.am': [],
        'autogen.sh': [],
        'bootstrap.sh': [],
        'CMakeLists.txt': [],
        'Config.in': [],
    }

  def _discover_build_configurations(self) -> bool:
    """Helper to discover the build configuartions of a repository."""
    # Prepare targert repository
    target_path = self._prepare_repository()

    # Locate common build configuration files
    for root_dir, _, files in os.walk(target_path):
      for file in files:
        if file in self.target_files:
          full_path = os.path.join(root_dir, file)
          self.target_files[file].append(full_path)

    # Extract content of build files
    for files in self.target_files.values():
      for file in files:
        with open(file, 'r') as f:
          self.build_files[file.replace(target_path, '')] = f.read()

    return len(self.build_files) > 0

  def _initial_prompt(self, results: list[Result]) -> Prompt:  # pylint: disable=unused-argument
    """Constructs initial prompt of the agent."""
    prompt = self.llm.prompt_type()(None)

    # Extract build configuration files content
    build_files_str = []
    for file, content in self.build_files.items():
      target_str = templates.LLM_BUILD_FILE_TEMPLATE.replace('{PATH}', file)
      target_str = target_str.replace('{CONTENT}', content)
      build_files_str.append(target_str)

    # Extract template Dockerfile content
    dockerfile_str = templates.CLEAN_OSS_FUZZ_DOCKER
    dockerfile_str = dockerfile_str.replace('{additional_packages}', '')
    dockerfile_str = dockerfile_str.replace('{fuzzer_dir}', '$SRC/')
    dockerfile_str = dockerfile_str.replace('{repo_url}', self.github_url)
    dockerfile_str = dockerfile_str.replace('{project_repo_dir}',
                                            self.github_url.split('/')[-1])

    # Prepare prompt problem string
    problem = templates.LLM_PROBLEM.replace('{BUILD_FILES}',
                                            '\n'.join(build_files_str))
    problem = problem.replace('{DOCKERFILE}', dockerfile_str)
    problem = problem.replace('{FUZZER}', self.harness_code)
    problem = problem.replace('{FUZZING_FILE}',
                              self.harness_path.split('/')[-1])

    headers = self._discover_headers()
    problem = problem.replace('{HEADERS}',
                              ','.join(headers[:SAMPLE_HEADERS_COUNT]))

    prompt.add_priming(templates.LLM_PRIMING)
    prompt.add_problem(problem)

    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    if not self._discover_build_configurations():
      logger.info('No known build configuration.',
                  self.name,
                  trial=result_history[-1].trial)
      return BuildResult(benchmark=result_history[-1].benchmark,
                         trial=result_history[-1].trial,
                         work_dirs=result_history[-1].work_dirs,
                         author=self,
                         chat_history={self.name: ''})

    return super().execute(result_history)


class AutoDiscoveryBuildScriptAgent(BuildScriptAgent):
  """Generate a working Dockerfile and build script from scratch
  with LLM auto discovery"""

  def _initial_prompt(self, results: list[Result]) -> Prompt:  # pylint: disable=unused-argument
    """Constructs initial prompt of the agent."""
    prompt = self.llm.prompt_type()(None)

    # Extract template Dockerfile content
    dockerfile_str = templates.CLEAN_OSS_FUZZ_DOCKER
    dockerfile_str = dockerfile_str.replace('{additional_packages}', '')
    dockerfile_str = dockerfile_str.replace('{repo_url}', self.github_url)
    dockerfile_str = dockerfile_str.replace('{project_repo_dir}',
                                            self.github_url.split('/')[-1])

    # Prepare prompt problem string
    problem = templates.LLM_AUTO_DISCOVERY
    problem = problem.replace('{PROJECT_NAME}', self.github_url.split('/')[-1])
    problem = problem.replace('{DOCKERFILE}', dockerfile_str)
    problem = problem.replace('{MAX_DISCOVERY_ROUND}', str(MAX_DISCOVERY_ROUND))
    problem = problem.replace('{FUZZING_FILE}',
                              self.harness_path.split('/')[-1])

    prompt.add_priming(templates.LLM_PRIMING)
    prompt.add_problem(problem)

    return prompt

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    prompt = self.llm.prompt_type()(None)

    if response:
      prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                    prompt)

      if self.discovery_stage:
        # Relay the command output back to LLM
        feedback = templates.LLM_DOCKER_FEEDBACK
        feedback = feedback.replace('{RESULT}', self.last_result)
        prompt.add_problem(feedback)
      else:
        # Check result and try building with the new builds script
        prompt = self._container_handle_conclusion(cur_round, response,
                                                   build_result, prompt)

        if prompt is None:
          return None

    if not response or not prompt or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, cur_round, response, prompt)

    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    self._prepare_repository()
    return super().execute(result_history)
