#!/usr/bin/env python3
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
"""Build fixer tooling."""

import os
import re
import shutil
import subprocess
import sys
import uuid
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from experimental.build_fixer import templates
from llm_toolkit import models
from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.base_tool import BaseTool
from tool.container_tool import ProjectContainerTool


class BuildFixAgent(BaseAgent):
  """Agent for fixing OSS-Fuzz project builds."""

  def __init__(self, llm: LLM, project_name, work_dirs, args):
    super().__init__(trial=1, llm=llm, args=args)
    self.project_name = project_name
    self.original_project_name = project_name
    self.work_dirs = work_dirs
    self.last_status = False
    self.last_result = ''
    self.compiles = False
    self.check_all_passed = False
    self.initial_error_result = ''
    self.trial = 0

    self.success_build_script = ''

    self.projet_language = oss_fuzz_checkout.get_project_language(
        self.project_name)

  def _initial_prompt(self, results: list[Result]):
    """Creates the initial prompt for the build fixer agent."""
    with open(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     self.project_name, 'build.sh'), 'r') as f:
      build_script = f.read()

    with open(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     self.project_name, 'Dockerfile'), 'r') as f:
      dockerfile = f.read()

    prompt = self.llm.prompt_type()(None)

    template_prompt = templates.BUILD_FIX_PROBLEM
    template_prompt.replace('{DOCKERFILE}', dockerfile)
    template_prompt.replace('{BUILD_SCRIPT}', build_script)
    template_prompt.replace('{LOGS}', self.initial_error_result[-300:])
    template_prompt.replace('{MAX_DISCOVERY_ROUND}', str(self.args.max_round))

    if self.projet_language.lower() == 'python':
      template_prompt.replace('{LANGUAGE_SPECIFICS}',
                              templates.PYTHON_SPECIFICS)
    else:
      template_prompt.replace('{LANGUAGE_SPECIFICS}', '')
    #prompt.add_priming(template_prompt)

    prompt.add_priming(templates.BUILD_FIXER_LLM_PRIMING)
    prompt.add_problem(template_prompt)
    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the build fixer agent."""
    result_name = oss_fuzz_checkout.prepare_project_image_by_name(
        self.project_name)

    if not result_name:
      logger.info(f'Failed to prepare project image for {self.project_name}.',
                  trial=self.trial)
      sys.exit(1)

    self.project_name = result_name.split('/')[-1]
    benchmark = Benchmark(self.project_name, self.project_name, '', '', '', '',
                          [], '')

    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    result = self.inspect_tool.compile(
        extra_commands=' && rm -rf /out/* > /dev/null')

    # If the build succeeded, we can exit
    if result.returncode == 0:
      logger.info(f'Build succeeded for {self.project_name}.', trial=self.trial)
      logger.info('Nothing to fix.', trial=self.trial)
      sys.exit(0)

    self.initial_error_result = result.stderr

    prompt = self._initial_prompt(result_history)

    build_result = BuildResult(benchmark=benchmark,
                               trial=0,
                               work_dirs=self.work_dirs,
                               author=self,
                               chat_history={self.name: ''})

    # LLM iteration
    cur_round = 0
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt:
        response = self.chat_llm(cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=cur_round)
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)
        if not prompt:
          break
      cur_round += 1
    finally:
      self.inspect_tool.terminate()
    return build_result

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

  def _test_check_build(self, tool: BaseTool, build_script) -> bool:
    """Helper to test the generated build script for introspector build."""

    # Create a copy of the original project name
    target_dst = self.original_project_name + '-copy-' + str(
        uuid.uuid4().hex)[:8]
    shutil.copytree(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     self.original_project_name),
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects', target_dst))

    self.success_build_script = build_script
    # Overwrite the build script with the new one
    with open(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects', target_dst,
                     'build.sh'), 'w') as f:
      f.write(build_script)
    # Build project
    try:
      subprocess.check_call(
          f'python3 infra/helper.py build_fuzzers {target_dst}',
          cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
          shell=True)
    except:
      return False

    try:
      subprocess.check_call(f'python3 infra/helper.py check_build {target_dst}',
                            cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
                            shell=True)
    except:
      return False
    return True

  def _container_handle_bash_commands(self, response: str, tool: BaseTool,
                                      prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    # Initialise variables
    prompt_text = ''
    success = False
    self.invalid = False
    self.missing_binary = False

    # Retrieve data from response
    build_script = self._parse_tag(response, 'bash')
    commands = '; '.join(self._parse_tags(response, 'command'))

    if commands:
      self.discovery_stage = True

      # Execute the command directly, then return the formatted result
      result = tool.execute(commands)
      prompt_text = self._format_bash_execution_result(result,
                                                       previous_prompt=prompt)
      if result.returncode == 0:
        success = True
    elif build_script:
      self.discovery_stage = False

      # Restart the container to ensure a fresh session for test
      if isinstance(tool, ProjectContainerTool):
        tool.terminate()
      tool = ProjectContainerTool(benchmark=tool.benchmark, name='test')
      self.inspect_tool = tool

      # Fix shebang to ensure docker image failing is reflected.
      lines = build_script.split('\n')
      if lines[0].startswith("#!"):
        lines[0] = "#!/bin/bash -eu"
      else:
        lines = ["#!/bin/bash -eu"] + lines
      build_script = '\n'.join(lines)

      # Update build script
      if isinstance(tool, ProjectContainerTool):
        tool.write_to_file(build_script, tool.build_script_path)

        # Test and parse result
        result = tool.execute('compile')
        format_result = self._format_bash_execution_result(
            result, previous_prompt=prompt)
        prompt_text = self._parse_tag(format_result, 'stderr') + '\n'
        if result.returncode == 0:
          if result.returncode == 0:
            success = True
            self.compiles = True

            # Test check_all passes
            if self._test_check_build(self.inspect_tool, build_script):
              self.check_all_passed = True
            else:
              self.check_all_passed = False
          else:
            # Fuzzer binary not compiled correctly
            success = False
            self.missing_binary = True
    else:
      self.invalid = True

    self.last_status = success
    self.last_result = prompt_text

    return prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   build_result: BuildResult,
                                   prompt: Prompt) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new build script from LLM."""

    # Don't need to check for invalid result
    if self.invalid:
      return prompt

    # Execution fail
    if not self.compiles:
      retry = templates.LLM_RETRY.replace('{BASH_RESULT}', self.last_result)
      prompt.add_problem(retry)

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt
    if not self.check_all_passed:
      retry = templates.LLM_RETRY_CHECK_ALL.replace('{BASH_RESULT}',
                                                    self.last_result)
      prompt.add_problem(retry)

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt
    # Build script succeeded
    return None

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    prompt = self.llm.prompt_type()(None)

    if response:
      prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                    prompt)

      prompt = self._container_handle_conclusion(cur_round, response,
                                                 build_result, prompt)
      if prompt is None:
        logger.info('Succeeded fixing build script', trial=self.trial)
        logger.info(self.success_build_script, trial=self.trial)
        return None

    return prompt


def fix_build(args, oss_fuzz_base):
  """Fixes the build of a given project."""

  project_name = args.project
  oss_fuzz_checkout.OSS_FUZZ_DIR = oss_fuzz_base
  work_dirs = WorkDirs(args.work_dirs, keep=True)

  # Prepare LLM model
  llm = models.LLM.setup(
      ai_binary=os.getenv('AI_BINARY', ''),
      name=args.model,
      max_tokens=4096,
      num_samples=1,
      temperature=0.4,
      temperature_list=[],
  )
  llm.MAX_INPUT_TOKEN = 25000

  # Set up Build fixer agent
  agent = BuildFixAgent(llm, project_name, work_dirs, args)

  # Execute the agent
  agent.execute([])
