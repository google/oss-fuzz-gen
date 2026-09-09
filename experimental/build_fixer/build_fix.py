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

import glob
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Optional

import yaml

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

FIXER_TOOLS = [{
    'type': 'function',
    'name': 'test_build_script',
    'description':
        ('Tests a build script against the target project. Use this for '
         'testing build scripts that may work.'),
    'parameters': {
        'type': 'object',
        'properties': {
            'build_script': {
                'type': 'string',
                'description': 'Bash script that builds the project.'
            }
        },
        'required': ['build_script'],
        'additionalProperties': False
    }
}, {
    'type':
        'function',
    'name':
        'test_build_script_and_dockerfile',
    'description':
        'Tests a build script and Dockerfile against target project.',
    'parameters': {
        'type': 'object',
        'properties': {
            'build_script': {
                'type': 'string',
                'description': 'Bash script that builds the project.'
            },
            'dockerfile': {
                'type': 'string',
                'description': 'Dockerfile that builds the project.'
            }
        },
        'required': ['build_script', 'dockerfile'],
        'additionalProperties': False
    }
}, {
    'type': 'function',
    'name': 'run_commands_in_container',
    'description':
        ('Runs commands in the project container for exploring the project '
         'or its dependencies.'),
    'parameters': {
        'type': 'object',
        'properties': {
            'command': {
                'type':
                    'string',
                'description':
                    'Bash commands separated by \';\' to run in the container.'
            }
        },
        'required': ['command'],
        'additionalProperties': False
    }
}]

DISCOVERY_COMMAND_TIMEOUT_SECONDS = 120


def _fix_build_agent_model_config(
    model_name: str,
    environ: Optional[dict[str, str]] = None) -> dict[str, str]:
  """Maps an oss-fuzz-gen model name to the bundled agent's LiteLLM config.

  This function only translates configuration. It does not contact a model
  provider, which makes the provider-specific paths testable without API
  credentials.
  """
  env = environ if environ is not None else os.environ
  requested = (model_name or '').strip()
  lower = requested.lower()

  def first(*names: str, default: str = '') -> str:
    for name in names:
      value = env.get(name, '').strip()
      if value:
        return value
    return default

  if lower in ('openai_compatible', 'deepseek') or 'deepseek' in lower:
    model = first('FIX_BUILD_AGENT_MODEL',
                  'OPENAI_COMPATIBLE_MODEL',
                  'DEEPSEEK_MODEL',
                  default='deepseek-chat')
    if not model.startswith('deepseek/'):
      model = f'deepseek/{model}'
    return {
        'model':
            model,
        'api_base':
            first('FIX_BUILD_AGENT_API_BASE',
                  'OPENAI_COMPATIBLE_BASE_URL',
                  'DEEPSEEK_BASE_URL',
                  default='https://api.deepseek.com'),
        'api_key':
            first('API_KEY', 'OPENAI_COMPATIBLE_API_KEY', 'DEEPSEEK_API_KEY'),
        'auth':
            'api_key',
    }

  if lower in ('gpt-3.5-turbo-azure', 'gpt-4-azure',
               'gpt-4o-azure') or ('azure' in lower):
    deployment = first('FIX_BUILD_AGENT_AZURE_DEPLOYMENT',
                       'AZURE_OPENAI_DEPLOYMENT_NAME',
                       'AZURE_OPENAI_DEPLOYMENT')
    if not deployment:
      raise ValueError(
          'Azure OpenAI requires FIX_BUILD_AGENT_AZURE_DEPLOYMENT or '
          'AZURE_OPENAI_DEPLOYMENT_NAME.')
    return {
        'model': f'azure/{deployment}',
        'api_base': first('AZURE_OPENAI_ENDPOINT'),
        'api_key': first('AZURE_OPENAI_API_KEY'),
        'api_version': first('AZURE_OPENAI_API_VERSION', default='2024-02-01'),
        'auth': 'api_key',
    }

  if lower.startswith('vertex_ai_claude'):
    claude_models = {
        'vertex_ai_claude-3-haiku': 'claude-3-haiku@20240307',
        'vertex_ai_claude-3-opus': 'claude-3-opus@20240229',
        'vertex_ai_claude-3-5-sonnet': 'claude-3-5-sonnet@20240620',
    }
    model = claude_models.get(lower, requested.removeprefix('vertex_ai/'))
    if not model.startswith('claude-'):
      model = f'claude-{model}'
    return {
        'model': f'vertex_ai/{model}',
        'api_base': '',
        'api_key': '',
        'auth': 'adc',
    }

  if lower.startswith('vertex_ai_gemini'):
    gemini_models = {
        'vertex_ai_gemini-pro': 'gemini-1.0-pro',
        'vertex_ai_gemini-2-flash': 'gemini-2.0-flash-001',
        'vertex_ai_gemini-2-5-flash': 'gemini-2.5-flash',
        'vertex_ai_gemini-2-5-pro': 'gemini-2.5-pro',
        'vertex_ai_gemini-3-flash': 'gemini-3-flash-preview',
        'vertex_ai_gemini-3-pro': 'gemini-3-pro-preview',
        'vertex_ai_gemini-3-1-pro': 'gemini-3.1-pro-preview',
    }
    model = gemini_models.get(lower)
    if model is None:
      model = lower.removeprefix('vertex_ai_').replace('-chat', '')
    return {
        'model': f'vertex_ai/{model}',
        'api_base': '',
        'api_key': '',
        'auth': 'adc',
    }

  if lower.startswith('gemini_api_key'):
    model = first('FIX_BUILD_AGENT_GEMINI_MODEL',
                  'GEMINI_MODEL',
                  default='gemini-2.5-flash')
    return {
        'model': f'gemini/{model}',
        'api_base': '',
        'api_key': first('GEMINI_API_KEY', 'GOOGLE_API_KEY'),
        'auth': 'api_key',
    }

  # The original OpenAI model names are provider-neutral in oss-fuzz-gen.
  # Explicitly qualify them for LiteLLM so the child process uses OpenAI.
  model = requested or 'gpt-3.5-turbo'
  if model.startswith('chatgpt-'):
    model = model.removeprefix('chatgpt-')
  return {
      'model': f'openai/{model}',
      'api_base': first('OPENAI_BASE_URL'),
      'api_key': first('OPENAI_API_KEY'),
      'auth': 'api_key',
  }


class BuildFixAgent(BaseAgent):
  """Agent for fixing OSS-Fuzz project builds."""

  def __init__(self,
               llm: LLM,
               project_name,
               work_dirs,
               args,
               use_tools: bool = True,
               trial: int = 1):
    super().__init__(trial=trial, llm=llm, args=args)
    # Keep an explicit attribute for static analyzers and logging adapters.
    self.trial = trial
    self.project_name = project_name
    self.original_project_name = project_name
    self.work_dirs = work_dirs
    self.last_status = False
    self.last_result = ''
    self.compiles = False
    self.check_all_passed = False
    self.initial_error_result = ''

    self.use_tools = use_tools

    self.success_build_script = ''
    self.success_dockerfile = ''

    self.project_language = oss_fuzz_checkout.get_project_language(
        self.project_name)

  def _strip_license_from_file(self, file_content: str) -> str:
    """Strips the license header from a file content."""
    # Strip first comments in a file.
    new_content = ''
    past_license = False
    for line in file_content.splitlines():
      if past_license:
        new_content += line + '\n'
        continue

      if '#################' in line:
        past_license = True
        continue

      if line.startswith('#') and 'bash' not in line or 'python' not in line:
        continue
      new_content += line + '\n'
    return new_content

  def _initial_prompt(self, results: list[Result], is_tools: bool = True):  # pylint: disable=unused-argument
    """Creates the initial prompt for the build fixer agent."""
    with open(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     self.project_name, 'build.sh'), 'r') as f:
      build_script = self._strip_license_from_file(f.read())

    with open(
        os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects',
                     self.project_name, 'Dockerfile'), 'r') as f:
      dockerfile = self._strip_license_from_file(f.read())

    prompt = self.llm.prompt_type()(None)

    if is_tools:
      template_prompt = templates.BUILD_FIX_PROBLEM_TOOLS
    else:
      template_prompt = templates.BUILD_FIX_PROBLEM
    template_prompt = template_prompt.replace('{DOCKERFILE}', dockerfile)
    template_prompt = template_prompt.replace('{BUILD_SCRIPT}', build_script)
    template_prompt = template_prompt.replace('{LOGS}',
                                              self.initial_error_result[-4000:])
    template_prompt = template_prompt.replace('{MAX_DISCOVERY_ROUND}',
                                              str(self.args.max_round))

    if self.project_language.lower() == 'python':
      template_prompt = template_prompt.replace('{LANGUAGE_SPECIFICS}',
                                                templates.PYTHON_SPECIFICS)
    elif self.project_language.lower() in ['c', 'c++']:
      template_prompt = template_prompt.replace('{LANGUAGE_SPECIFICS}',
                                                templates.C_CPP_SPECIFICS)
    else:
      template_prompt = template_prompt.replace('{LANGUAGE_SPECIFICS}', '')
    #prompt.add_priming(template_prompt)

    prompt.add_priming(templates.BUILD_FIXER_LLM_PRIMING)
    prompt.add_problem(template_prompt)
    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the build fixer agent.
    Creates a container tool and performs an initial build attempt.
    The output of the build is then used to generate a prompt,
    and the agent then goes into the iterative process.
    """

    # Prepare an initial image build.
    result_name = oss_fuzz_checkout.prepare_project_image_by_name(
        self.project_name)

    if not result_name:
      logger.info(f'Failed to prepare project image for {self.project_name}.',
                  trial=self.trial)
      benchmark = result_history[-1].benchmark
      return BuildResult(
          benchmark=benchmark,
          trial=self.trial,
          work_dirs=self.work_dirs,
          compile_error='Failed to prepare project image.',
          author=self,
          chat_history={self.name: 'Failed to prepare project image.'})

    image_name = result_name
    self.project_name = image_name.split('/')[-1]
    benchmark = (result_history[-1].benchmark if result_history else Benchmark(
        self.project_name, self.project_name, self.project_language, '', '', '',
        [], ''))
    container_benchmark = Benchmark(self.project_name, self.project_name,
                                    benchmark.language, '', '', '', [], '')

    # Initial run of compile.
    self.inspect_tool = ProjectContainerTool(container_benchmark,
                                             name='inspect',
                                             image_name=image_name)
    result = self.inspect_tool.compile(
        extra_commands=' && rm -rf /out/* > /dev/null')

    # If the build succeeded, we can exit
    if result.returncode == 0:
      logger.info(f'Build succeeded for {self.project_name}.', trial=self.trial)
      logger.info('Nothing to fix.', trial=self.trial)
      self.inspect_tool.terminate()
      return BuildResult(
          benchmark=benchmark,
          trial=self.trial,
          work_dirs=self.work_dirs,
          compiles=True,
          compile_log=result.stdout,
          binary_exists=True,
          is_function_referenced=True,
          author=self,
          chat_history={
              self.name: 'Initial OSS-Fuzz build succeeded. Nothing to fix.'
          })

    self.initial_error_result = result.stderr

    # Prepare initial prompt.
    prompt = self._initial_prompt(result_history, self.use_tools)
    build_result = BuildResult(benchmark=benchmark,
                               trial=0,
                               work_dirs=self.work_dirs,
                               author=self,
                               chat_history={self.name: ''})
    if self.use_tools:
      self._agent_run_function_based_loop(prompt, build_result)
    else:
      self._agent_raw_loop(prompt, build_result)
    build_result.compiles = self.compiles
    build_result.binary_exists = self.check_all_passed
    build_result.is_function_referenced = self.check_all_passed
    build_result.compile_error = ('' if self.check_all_passed else
                                  self.last_result)
    build_result.compile_log = self.last_result
    build_result.build_script_source = self.success_build_script
    build_result.chat_history = {
        self.name:
            self.success_build_script if self.check_all_passed else
            (self.last_result or self.initial_error_result)
    }
    return build_result

  def _test_buildscript_and_dockerfile(self, tool_call, build_script,
                                       dockerfile):
    """Tests a build script and Dockerfile against the target project."""
    build_fuzzers_result, target_dst = self._test_build_fuzzers(
        build_script, dockerfile)
    if build_fuzzers_result.returncode != 0:
      logger.info('Build failed.', trial=self.trial)
      parsed_stdout = build_fuzzers_result.stdout
      parsed_stdout = self._simple_truncate_build_output(parsed_stdout)

      logger.info('Parsed stdout: %s', parsed_stdout, trial=self.trial)

      # Prepare for next iteration by adding messages to the chat.
      self.llm.messages.append(tool_call)
      self.llm.messages.append({
          'type': 'function_call_output',
          'call_id': tool_call.call_id,
          'output': str(parsed_stdout)
      })
      self.working_prompt = None

    else:
      logger.info('Build succeeded.', trial=self.trial)
      # Testing fuzzers run.
      test_run_result = self._test_check_fuzzers(target_dst)
      if test_run_result.returncode == 0:
        logger.info('Fuzzers run successfully.', trial=self.trial)
        self.success_build_script = build_script
        self.success_dockerfile = dockerfile

        self.exit_condition_met = True
      else:
        logger.info('Fuzzers run failed.', trial=self.trial)
        prompt_text = test_run_result.stdout
        # Prepare for next iteration by adding messages to the chat.
        self.llm.messages.append(tool_call)
        self.llm.messages.append({
            'type': 'function_call_output',
            'call_id': tool_call.call_id,
            'output': str(prompt_text)
        })

        self.working_prompt = None

  def _func_handle_run_commands_in_container(self, tool_call, command_string):
    """Runs a command string in the project container."""

    # Execute the command directly, then return the formatted result
    commands = command_string
    logger.info('LLM Requested commands: %s', commands, trial=self.trial)
    result = self.inspect_tool.execute(self._with_discovery_timeout(commands))
    prompt_text = self._format_bash_execution_result(
        result, previous_prompt=self.working_prompt)

    prompt_text = self._simple_truncate_build_output(prompt_text)

    # Extend messages to prepare for next iteration.
    self.llm.messages.append(tool_call)
    self.llm.messages.append({
        'type': 'function_call_output',
        'call_id': tool_call.call_id,
        'output': str(prompt_text)
    })
    self.working_prompt = None

  def _log_success(self):
    """Utility funciton to log success of fixing."""
    logger.info('Succeeded fixing build script', trial=self.trial)
    logger.info('-' * 25 + ' Build script: ' + '-' * 25, trial=self.trial)
    logger.info(self.success_build_script, trial=self.trial)
    logger.info('-' * 60, trial=self.trial)

  def _load_tool_arguments(self, tool_call: Any) -> Optional[dict]:
    """Loads the arguments for a tool call."""
    try:
      return json.loads(tool_call.arguments)
    except json.JSONDecodeError as e:
      logger.error('Failed to decode tool call arguments: %s',
                   e,
                   trial=self.trial)

    # Getting here means the arguments were not valid JSON.
    # This happens sometimes, and to overcome this we extract
    # the arguments using some simple manual parsing.
    args = {}

    # 1: find the relevant function
    # 2: For each argument of the function extract that
    # keyword from the response.
    for function_tool in FIXER_TOOLS:
      if function_tool['name'] == tool_call.name:
        for arg in function_tool['parameters']['properties']:
          # Extract the argument value from the response.
          val = self._extract_argument_from_broken_json(tool_call.arguments,
                                                        arg)
          args[arg] = val

        if len(args) != len(function_tool['parameters']['properties']):
          return None
    return args

  def _extract_argument_from_broken_json(self, raw_response, key):
    """Extracts a single argument from a broken JSON response."""
    # Find the first key
    search_word = f'"{key}":'
    location_idx = raw_response.find(search_word)
    start_idx = location_idx + len(search_word)

    # Find the next two quotes, and take everything within them.
    quote_locations = []
    for idx in range(len(raw_response[start_idx:])):
      if raw_response[idx + start_idx] == '"':
        # If this is escaped, discount
        if raw_response[idx + start_idx - 1] == '\\':
          continue
        # We have a quote
        quote_locations.append(idx + start_idx)
    if len(quote_locations) == 2:
      return raw_response[quote_locations[0] + 1:quote_locations[1]]
    return None

  def _dispatch_tool_call(self, tool_call: Any) -> int:
    """Dispatches a function call to the appropriate handler."""
    arguments = self._load_tool_arguments(tool_call)
    if arguments is None:
      return 0
    if tool_call.name == 'test_build_script_and_dockerfile':
      self._test_buildscript_and_dockerfile(tool_call,
                                            arguments['build_script'],
                                            arguments['dockerfile'])
      return 1
    if tool_call.name == 'test_build_script':
      self._test_buildscript_and_dockerfile(tool_call,
                                            arguments['build_script'], '')
      return 1
    if tool_call.name == 'run_commands_in_container':
      self._func_handle_run_commands_in_container(tool_call,
                                                  arguments['command'])
      return 1

    logger.info('Unsupported tool call: %s', tool_call.name, trial=self.trial)
    return 0

  def _agent_run_function_based_loop(
      self, prompt: Optional[Prompt], build_result: BuildResult) -> None:  # pylint: disable=unused-argument
    """Runs the agent loop using a function-based approach."""
    self.working_prompt = prompt
    # Agent loop
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())

      cur_round = 0
      self.exit_condition_met = False
      # Function execution and LLM communication loop.
      while self.exit_condition_met is False:
        logger.info(f'Agent Round {cur_round}', trial=self.trial)

        # Increment the round counter, but trigger exit condition if max
        # rounds reached.
        if cur_round > self.args.max_round:
          logger.info('Max discovery rounds reached (%s).',
                      self.args.max_round,
                      trial=self.trial)
          break
        cur_round += 1

        # Send prompt to LLM and get response.
        logger.info('Sending prompt to LLM', trial=self.trial)
        response = self.chat_llm_with_tools(client, self.working_prompt,
                                            FIXER_TOOLS, self.trial)

        if not response:
          logger.info('LLM did not return a response, skipping this round.',
                      trial=self.trial)
          continue

        # Handle LLM tool calls.
        tools_analysed = 0
        logger.info('Iterating response output', trial=self.trial)
        for tool_call in response.output:
          logger.info('- Response out:' + str(tool_call), trial=self.trial)
          if tool_call.type != 'function_call':
            continue

          logger.info('Handling tool call %s', tool_call.name, trial=self.trial)
          logger.info('Tool call arguments: %s',
                      tool_call.arguments,
                      trial=self.trial)
          tools_analysed += self._dispatch_tool_call(tool_call)

        # If no tool calls were made prepare LLM response saying we do not
        # understand the message received.
        if tools_analysed == 0 and not self.exit_condition_met:
          logger.info(
              'Did not execute any tool calls and there is no exit condition.',
              trial=self.trial)
          self.working_prompt = self.llm.prompt_type()(None)
          self.working_prompt.add_problem(
              'I was unable to interpret your last message. Use tool '
              'calls to direct this process instead of messages.')

      # Post LLM communication and function execution loop.
      # Log details on success.
      if self.exit_condition_met:
        self._log_success()

      # TODO (David): Add handling for "why did we not succeed" case.
    finally:
      self.inspect_tool.terminate()

  def _agent_raw_loop(self, prompt: Optional[Prompt],
                      build_result: BuildResult) -> None:
    """Runs the agent loop, sending prompts to the LLM and handling
    responses."""
    # Agent loop
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      final_prompt_sent = False
      final_response_consumed = False
      while prompt:
        logger.info(f'Agent Round {self.trial}', trial=self.trial)
        if self.trial >= self.args.max_round and not final_prompt_sent:
          prompt.add_problem(templates.FINAL_BUILD_SCRIPT_REQUIRED)
          final_prompt_sent = True

        # Pass prompt history to LLM and get response.
        logger.info('Sending prompt to LLM', trial=self.trial)
        response = self.chat_llm(self.trial,
                                 client=client,
                                 prompt=prompt,
                                 trial=self.trial)

        # Handle LLM response.
        logger.info('Handling LLM response', trial=self.trial)
        prompt = self._handle_llm_reponse(response, build_result)
        if not prompt:
          break
        if self.trial >= self.args.max_round:
          if final_prompt_sent and final_response_consumed:
            logger.info(
                f'Max discovery rounds reached ({self.args.max_round}).',
                trial=self.trial)
            break
          prompt.add_problem(templates.FINAL_BUILD_SCRIPT_REQUIRED)
          final_prompt_sent = True
          final_response_consumed = True
        self.trial += 1
    finally:
      self.inspect_tool.terminate()

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the tag from LLM response."""
    patterns = [rf'<{tag}>(.*?)</{tag}>', rf'```{tag}(.*?)```']

    # Matches both xml and code style tags
    for pattern in patterns:
      match = re.search(pattern, response, re.DOTALL)
      if match:
        return match.group(1).strip()

    return ''

  def _with_discovery_timeout(self, command: str) -> str:
    """Wraps an exploratory command so it cannot stall the agent loop."""
    return (f'timeout {DISCOVERY_COMMAND_TIMEOUT_SECONDS}s bash -lc '
            f'{shlex.quote(command)}')

  def _parse_tags(self, response: str, tag: str) -> list[str]:
    """Parses the tags from LLM response."""
    patterns = [rf'<{tag}>(.*?)</{tag}>', rf'```{tag}(.*?)```']
    found_matches = []

    # Matches both xml and code style tags
    for pattern in patterns:
      matches = re.findall(pattern, response, re.DOTALL)
      found_matches.extend([content.strip() for content in matches])

    return found_matches

  def _test_build_fuzzers(
      self,
      build_script: str,
      dockerfile: str = '') -> tuple[subprocess.CompletedProcess, str]:
    """Runs OSS-Fuzz's build_fuzzers command with the provided build script."""
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

    if dockerfile:
      # Overwrite the Dockerfile with the new one
      with open(
          os.path.join(oss_fuzz_checkout.OSS_FUZZ_DIR, 'projects', target_dst,
                       'Dockerfile'), 'w') as f:
        f.write(dockerfile)

    # Build project
    cmd = ['python3', 'infra/helper.py', 'build_fuzzers', target_dst]
    result = subprocess.run(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)
    return result, target_dst

  def _test_check_fuzzers(self, target_dst) -> subprocess.CompletedProcess:
    """Runs OSS-Fuzz's check_build command to evaluate build fuzzers."""

    cmd = ['python3', 'infra/helper.py', 'check_build', target_dst]
    result = subprocess.run(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                            text=True,
                            encoding='utf-8',
                            errors='ignore',
                            cwd=oss_fuzz_checkout.OSS_FUZZ_DIR)
    return result

  def _simple_truncate_build_output(self, output: str) -> str:
    """Truncates the build output to a manageable size."""
    if len(output) > 8000:
      return output[:1500] + '\n... (truncated)' + output[-6500:]
    return output

  def _parse_llm_reponse_and_operate(self, response: str, tool: BaseTool,
                                     prompt: Prompt) -> Prompt:
    """Parses and LLM response and takes appropriate action. This includes
    parsing bash commands to be executed in the container tool or extracting
    the build script and testing it for compilation."""
    # Initialise variables
    prompt_text = ''
    success = False
    self.invalid = False
    self.missing_binary = False

    logger.info('=' * 80, trial=self.trial)
    logger.info(response, trial=self.trial)
    logger.info('=' * 80, trial=self.trial)

    # Retrieve data from response
    build_script = self._parse_tag(response, 'bash')
    commands = '; '.join(self._parse_tags(response, 'command'))

    if commands:
      logger.info('LLM Requested commands: %s', commands, trial=self.trial)
      self.discovery_stage = True

      # Execute the command directly, then return the formatted result
      result = tool.execute(self._with_discovery_timeout(commands))
      if result.returncode == 124:
        result.stderr = (
            f'Command timed out after {DISCOVERY_COMMAND_TIMEOUT_SECONDS}s.\n'
            f'{result.stderr}')
      prompt_text = self._format_bash_execution_result(result,
                                                       previous_prompt=prompt)
      if result.returncode == 0:
        success = True
    elif build_script:
      logger.info('LLM Provided build script.', trial=self.trial)
      self.discovery_stage = False

      # Fix shebang to ensure docker image failing is reflected.
      lines = build_script.split('\n')
      if lines[0].startswith("#!"):
        lines[0] = "#!/bin/bash -eu"
      else:
        lines = ["#!/bin/bash -eu"] + lines
      build_script = '\n'.join(lines)

      build_result, target_dst = self._test_build_fuzzers(build_script)
      if build_result.returncode != 0:
        logger.info('Build failed.', trial=self.trial)
        parsed_stdout = build_result.stdout
        tag = '---------------------------------------------------------------'

        parsed_stdout = tag.join(parsed_stdout.split(tag)[3:])
        prompt_text = 'Build failed, this is the output:\n'
        parsed_stdout = self._simple_truncate_build_output(parsed_stdout)
        prompt_text += f'<out>{parsed_stdout}</out>'
        self.compiles = False
        self.check_all_passed = False
        success = False
      else:
        # Success build
        logger.info('Build succeeded.', trial=self.trial)
        logger.info('Testing fuzzers run.', trial=self.trial)
        test_run_result = self._test_check_fuzzers(target_dst)
        if test_run_result.returncode == 0:
          logger.info('Fuzzers run successfully.', trial=self.trial)
          self.check_all_passed = True
          success = True
          self.compiles = True
          self.success_build_script = build_script
        else:
          logger.info('Fuzzers run failed.', trial=self.trial)
          prompt_text = test_run_result.stdout
          self.compiles = True
          self.check_all_passed = False
          success = False
    else:
      self.invalid = True

    self.last_status = success
    self.last_result = prompt_text

    return prompt

  def _validate_operation_and_prepare_next_prompt(
      self, build_result: BuildResult, prompt: Prompt) -> Optional[Prompt]:
    """Interprets the results from operating on the LLM response and prepares
    a new prompt for the next round of interaction."""

    # Don't need to check for invalid result
    if self.invalid:
      return prompt

    # Execution fail
    if self.discovery_stage:
      logger.info('Validating BASH command response', trial=self.trial)
      # Still in bash mode.
      prompt.add_problem(self.last_result)

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt
    if not self.compiles:
      logger.info('Validation build failure response', trial=self.trial)
      retry = templates.LLM_RETRY.replace('{BASH_RESULT}', self.last_result)
      prompt.add_problem(retry)

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt
    if not self.check_all_passed:
      logger.info('Validating check_build failure', trial=self.trial)
      retry = templates.LLM_RETRY_CHECK_ALL.replace('{BASH_RESULT}',
                                                    self.last_result)
      prompt.add_problem(retry)

      # Store build result
      build_result.compiles = False
      build_result.compile_error = self.last_result

      return prompt
    # Build script succeeded
    return None

  def _handle_llm_reponse(self, response: str,
                          build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    prompt = self.llm.prompt_type()(None)

    if response:
      prompt = self._parse_llm_reponse_and_operate(response, self.inspect_tool,
                                                   prompt)
      logger.info('Handling conclusions', trial=self.trial)
      prompt = self._validate_operation_and_prepare_next_prompt(
          build_result, prompt)
      if prompt is None:
        logger.info('Succeeded fixing build script', trial=self.trial)
        logger.info('-' * 25 + ' Build script: ' + '-' * 25, trial=self.trial)
        logger.info(self.success_build_script, trial=self.trial)
        logger.info('-' * 60, trial=self.trial)
        return None

    return prompt


def fix_build(args, oss_fuzz_base, use_tools: bool = True):
  """Fixes the build of a given project."""

  project_name = args.project
  oss_fuzz_checkout.OSS_FUZZ_DIR = oss_fuzz_base

  # Disabling caching
  oss_fuzz_checkout.ENABLE_CACHING = False

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
  agent = BuildFixAgent(llm, project_name, work_dirs, args, use_tools=use_tools)

  # Execute the agent
  agent.execute([])


class ExternalBuildFixAgent(BaseAgent):
  """Adapter that runs an external fix-build-agent checkout as a subprocess."""

  def __init__(self, trial: int, llm: LLM, args, benchmark: Benchmark):
    super().__init__(trial=trial, llm=llm, args=args)
    self.benchmark = benchmark

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    raise NotImplementedError('ExternalBuildFixAgent is subprocess based.')

  def _write_external_projects_yaml(self, external_path: str) -> str:
    """Writes a one-project queue compatible with the external agent."""
    metadata = self.benchmark.metadata or {}
    project_entry = {
        'project':
            self.benchmark.project,
        'language':
            self.benchmark.language,
        'oss-fuzz_sha':
            metadata.get('oss_fuzz_sha') or metadata.get('oss-fuzz_sha')
            or metadata.get('oss-fuzz_sha'.replace('-', '_'), ''),
        'fuzzing_build_error_log':
            metadata.get('fuzzing_build_error_log', ''),
        'software_repo_url':
            metadata.get('software_repo_url', ''),
        'software_sha':
            metadata.get('software_sha', ''),
        'engine':
            metadata.get('engine', 'libfuzzer'),
        'sanitizer':
            metadata.get('sanitizer', 'address'),
        'architecture':
            metadata.get('architecture', 'x86_64'),
        'base_image_digest':
            metadata.get('base_image_digest', ''),
        'error_time':
            str(metadata.get('error_time', '')),
        'fixed_state':
            'no',
    }
    for optional_key in ['root_cause_commit', 'root_cause_workspace']:
      if metadata.get(optional_key):
        project_entry[optional_key] = metadata[optional_key]

    external_yaml = os.path.join(external_path, 'projects.yaml')
    with open(external_yaml, 'w') as f:
      yaml.safe_dump([project_entry], f, sort_keys=False)
    return external_yaml

  def _external_archive_dir(self) -> str:
    """Returns the project directory for full-agent artifacts.

    The full agent is invoked as a subprocess, but its artifacts are regular
    fix-build results. Keeping them directly under the project directory avoids
    an extra directory level that does not distinguish result types.
    """
    archive_dir = os.path.join(str(self.args.work_dirs.base), 'repair')
    os.makedirs(archive_dir, exist_ok=True)
    return archive_dir

  # pylint: disable=unused-argument
  def _copy_external_artifacts(self, external_path: str, log_path: str,
                               log_text: str) -> None:
    """Copies the external agent's own outputs into oss-fuzz-gen results."""
    archive_dir = self._external_archive_dir()
    for stale_name in [
        'agent.log', 'agent.stdout.txt', 'agent_logs', 'archive',
        'process_fixed', 'process_unfixed', 'project_repair_trace.json',
        'projects.yaml', 'fixed-files'
    ]:
      stale_path = os.path.join(archive_dir, stale_name)
      if os.path.isdir(stale_path):
        shutil.rmtree(stale_path, ignore_errors=True)
      elif os.path.exists(stale_path):
        os.remove(stale_path)

    shutil.copy2(log_path, os.path.join(archive_dir, 'run.log'))

    external_yaml = os.path.join(external_path, 'projects.yaml')
    if os.path.exists(external_yaml):
      shutil.copy2(external_yaml, os.path.join(archive_dir, 'input.yaml'))

    result_candidates = glob.glob(
        os.path.join(external_path, 'archive', self.benchmark.project,
                     'result_*.txt'))
    if result_candidates:
      latest_result = max(result_candidates, key=os.path.getmtime)
      shutil.copy2(latest_result, os.path.join(archive_dir, 'result.txt'))
    else:
      result_path = os.path.join(external_path, 'result.txt')
      if os.path.exists(result_path):
        shutil.copy2(result_path, os.path.join(archive_dir, 'result.txt'))

    fixed_candidates = glob.glob(
        os.path.join(external_path, 'process', 'fixed',
                     f'{self.benchmark.project}_*'))
    if fixed_candidates:
      latest_fixed = max(fixed_candidates, key=os.path.getmtime)
      trace_path = os.path.join(latest_fixed, 'project_repair_trace.json')
      if os.path.exists(trace_path):
        shutil.copy2(trace_path, os.path.join(archive_dir, 'repair-trace.json'))

      fixed_files_dir = os.path.join(archive_dir, 'fixed-files')
      os.makedirs(fixed_files_dir, exist_ok=True)
      config_dir = os.path.join(latest_fixed, 'configs', 'projects',
                                self.benchmark.project)
      for filename in ['Dockerfile', 'build.sh', 'project.yaml']:
        source = os.path.join(config_dir, filename)
        if os.path.exists(source):
          shutil.copy2(source, os.path.join(fixed_files_dir, filename))
      for patch_path in glob.glob(os.path.join(latest_fixed, 'diffs',
                                               '*.patch')):
        shutil.copy2(
            patch_path,
            os.path.join(fixed_files_dir, os.path.basename(patch_path)))
    else:
      trace_path = os.path.join(external_path, 'project_repair_trace.json')
      if os.path.exists(trace_path):
        shutil.copy2(trace_path, os.path.join(archive_dir, 'repair-trace.json'))

  def _read_external_result_success(self) -> Optional[bool]:
    """Reads the original fix_build_agent final report from copied artifacts."""
    result_path = os.path.join(self._external_archive_dir(), 'result.txt')
    if not os.path.exists(result_path):
      return None

    with open(result_path, encoding='utf-8', errors='ignore') as result_file:
      result_text = result_file.read()

    result_match = re.search(r'\[Result\]:\s*(.*)', result_text)
    if not result_match:
      return None

    result_value = result_match.group(1).upper()
    if 'SUCCESS' in result_value:
      return True
    if 'FAILURE' in result_value:
      return False
    return None

  def _external_env(self) -> dict[str, str]:
    """Builds an environment for the bundled full fix-build agent."""
    env = os.environ.copy()
    config = _fix_build_agent_model_config(self.args.model, env)
    env['FIX_BUILD_AGENT_MODEL'] = config['model']
    env['API_KEY'] = config['api_key']
    env['FIX_BUILD_AGENT_API_BASE'] = config['api_base']
    if config.get('api_version'):
      env['AZURE_API_VERSION'] = config['api_version']
    env.setdefault('FIX_BUILD_AGENT_SKIP_GH_AUTH_CHECK', '1')
    return env

  def _external_python(self, external_path: str) -> str:
    """Returns the Python interpreter for the external agent checkout."""
    candidates = [
        os.path.join(external_path, '.venv', 'bin', 'python'),
        '/opt/fix-build-agent-venv/bin/python',
    ]
    for candidate in candidates:
      if os.path.exists(candidate):
        return candidate
    return sys.executable

  def _resolve_external_path(self) -> str:
    """Resolves the agent checkout path in local and Cloud Build layouts."""
    configured_path = os.path.realpath(self.args.external_fix_build_agent_path)
    candidates = [
        configured_path,
        '/workspace/ofg/fix_build_agent',
        '/workspace/fix_build_agent',
        '/experiment/fix_build_agent',
    ]
    for candidate in candidates:
      if os.path.isdir(candidate):
        return candidate
    return configured_path

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Runs the external build-fix agent and collects its artifacts."""
    configured_path = os.path.realpath(self.args.external_fix_build_agent_path)
    external_path = self._resolve_external_path()
    logging.info('Configured external agent path: %s', configured_path)
    logging.info('External fix-build agent path: %s', external_path)
    logging.info('External fix-build agent path exists: %s',
                 os.path.isdir(external_path))
    logging.info('External fix-build agent cwd: %s', os.getcwd())
    logging.info('External fix-build agent Python: %s', sys.executable)
    for candidate in [
        external_path,
        '/experiment/fix_build_agent',
        '/workspace/ofg/fix_build_agent',
        '/workspace/fix_build_agent',
    ]:
      logging.info('External agent candidate: %s (exists=%s)', candidate,
                   os.path.exists(candidate))
    if os.path.isdir('/workspace/ofg'):
      tree_entries = []
      for root, dirs, files in os.walk('/workspace/ofg'):
        depth = root.removeprefix('/workspace/ofg').count(os.sep)
        if depth > 2:
          dirs[:] = []
          continue
        for name in sorted(dirs + files):
          tree_entries.append(os.path.join(root, name))
          if len(tree_entries) >= 200:
            break
        if len(tree_entries) >= 200:
          break
      logging.info('Cloud agent workspace tree (up to 200 entries): %s',
                   tree_entries)
    if not os.path.isdir(external_path):
      message = f'External fix build agent path does not exist: {external_path}'
      logging.error(message)
      return BuildResult(self.benchmark,
                         self.trial,
                         self.args.work_dirs,
                         compile_error=message,
                         author=self,
                         chat_history={self.name: message})

    external_yaml = self._write_external_projects_yaml(external_path)
    with tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8',
                                     delete=False) as log_file:
      log_path = log_file.name

    try:
      external_env = self._external_env()
      external_python = self._external_python(external_path)
      logging.info('External fix-build Python: %s (exists=%s)', external_python,
                   os.path.exists(external_python))
      command = [
          external_python, 'agent.py', '--projects-yaml', external_yaml,
          '--model', external_env['FIX_BUILD_AGENT_MODEL'], '--api-base',
          external_env['FIX_BUILD_AGENT_API_BASE'], '--skip-gh-auth-check'
      ]
      logging.info('External fix-build command: %s', command)
      logging.info('External projects YAML: %s (exists=%s)', external_yaml,
                   os.path.exists(external_yaml))
      process = subprocess.run(command,
                               cwd=external_path,
                               env=external_env,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               text=True,
                               encoding='utf-8',
                               errors='ignore',
                               check=False)
      log_text = process.stdout
      logging.info('External fix-build process return code: %s',
                   process.returncode)
      with open(log_path, 'w') as f:
        f.write(log_text)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      log_text = f'Failed to run external fix build agent: {exc}'
      process = subprocess.CompletedProcess([], 1, log_text, '')

    self._copy_external_artifacts(external_path, log_path, log_text)
    result_success = self._read_external_result_success()
    success = bool(result_success)
    if result_success is None:
      log_text = ('External fix_build_agent did not produce a parseable '
                  f'final result.txt.\n\n{log_text}')
    return BuildResult(
        benchmark=self.benchmark,
        trial=self.trial,
        work_dirs=self.args.work_dirs,
        compiles=success,
        compile_error='' if success else log_text[-8000:],
        compile_log=log_text,
        binary_exists=success,
        is_function_referenced=success,
        author=self,
        chat_history={
            self.name: f'External agent log: {log_path}\n\n{log_text[-8000:]}'
        })
