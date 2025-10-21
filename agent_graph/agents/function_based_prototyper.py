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
"""An LLM agent that uses function tools to generate fuzz harnesses."""

import json
import subprocess as sp
import time
from typing import Any, Optional

import logger
from agent_graph.agents.base_agent import BaseAgent
from data_prep import introspector
from experiment.workdir import WorkDirs
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, BuildResult, Result
from tool.container_tool import ProjectContainerTool

FUZZ_GEN_TOOLS = [
    #  {
    #    'type':
    #        'function',
    #    'name':
    #        'list_functions_in_project',
    #    'description':
    #        'Lists all functions in the project, including their names and source code.',
    #    'parameters': {
    #        'type': 'object',
    #        'properties': {
    #        },
    #        'additionalProperties': False
    #    }
    #},
    {
        'type': 'function',
        'name': 'get_source_code_of_function',
        'description': 'Gets the source code of a function.',
        'parameters': {
            'type': 'object',
            'properties': {
                'function_signature': {
                    'type':
                        'string',
                    'description':
                        'Signature of the function to get the source code of.'
                }
            },
            'required': ['function_signature'],
            'additionalProperties': False
        }
    },
    {
        'type': 'function',
        'name': 'run_commands_in_container',
        'description':
            ('Runs commands in the container where the fuzz harness is to '
             'be build. Only use this function to explore the build '
             'environment and target codebase. Do not use it for testing '
             'the building of a fuzzing harness source code.'),
        'parameters': {
            'type': 'object',
            'properties': {
                'command': {
                    'type':
                        'string',
                    'description': ('Bash commands separated by \';\' to '
                                    'run in the container.')
                }
            },
            'required': ['command'],
            'additionalProperties': False
        }
    },
    {
        'type': 'function',
        'name': 'test_fuzz_harness_build',
        'description':
            ('Tries to build the provided fuzzing harness. Use this function '
             'for testing whether the source code of a fuzzing harness builds.'
            ),
        'parameters': {
            'type': 'object',
            'properties': {
                'fuzzer_source_code': {
                    'type': 'string',
                    'description': 'Source code of the fuzzing harness.'
                }
            },
            'required': ['fuzzer_source_code'],
            'additionalProperties': False
        }
    }
]

FUNCTION_TOOL_INITIAL_PROMPT = '''You are a security engineer looking to create
a fuzz target for a specific function in a project. Your task is to generate
a simple fuzz target that can build successfully and is capable of
exercising the function under test. The fuzz target should be written in the
language of the project and should be able to compile with the provided build
script. The fuzz target should also be able to run in the provided container
environment.
You will be provided with the following information:
- The function under test, including its name and signature.
- The project language and file type.
You will also have access to a set of tools that can help you:
- List all functions in the project.
- Get the source code of a specific function.
- Run commands in the container where the fuzz target is to be built.
- Test the fuzz target build by compiling the provided source code.
You will interact with the tools to gather information and generate the fuzz
target. Your goal is to create a valid fuzz target that can be built and run
in the container environment, and that can exercise the function under test.
Make sure to follow the project conventions and best practices for writing
fuzz targets in the specific language. The fuzz target should be simple but
valid, and should not require any additional dependencies or libraries.

You are interacting with a fully automated system, so use the tools provided to you.
Do not ask for human help, but rather use the tools to gather information
and generate the fuzz target.

<target_function>
{FUNCTION_SIGNATURE}</target_function>

<project_language>
{PROJECT_LANGUAGE}</project_language>
'''

FUNCTION_REFINE_PROMPT = '''You are a security engineer looking to improve
a fuzz target for a specific function in a project. Your task is to refine
the fuzz target to overcome the issues found from running the fuzz target.

The fuzz target should be written in the
language of the project and should be able to compile with the provided build
script. The fuzz target should also be able to run in the provided container
environment.
You will be provided with the following information:
- The function under test, including its name and signature.
- The project language and file type.
- Structured information about the errors from the last run of the fuzz target.
You will also have access to a set of tools that can help you:
- List all functions in the project.
- Get the source code of a specific function.
- Run commands in the container where the fuzz target is to be built.
- Test the fuzz target build by compiling the provided source code.
You will interact with the tools to gather information and improve the fuzz
target. Your goal is to create a better fuzz target that can build and run
in the container environment, and that can exercise the function under test.
Make sure to follow the project conventions and best practices for writing
fuzz targets in the specific language. The fuzz target should be simple but
valid, and should not require any additional dependencies or libraries.

You are interacting with a fully automated system, so use the tools provided to you.
Do not ask for human help, but rather use the tools to gather information
and generate the fuzz target.

<target_function>
{FUNCTION_SIGNATURE}</target_function>

<project_language>
{PROJECT_LANGUAGE}</project_language>


<existing_fuzzer_source_code>
{FUZZER_SOURCE_CODE}</existing_fuzzer_source_code>

<structured_information_about_errors_from_previous_run>
{ERRORS}</structured_information_about_errors_from_previous_run>

The goal is to improve the fuzz target, and we will continue the process
until the improved fuzz target builds and runs.
'''


class FunctionToolPrototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""

    template_prompt = FUNCTION_TOOL_INITIAL_PROMPT
    template_prompt = template_prompt.replace('{FUNCTION_SIGNATURE}',
                                              self.benchmark.function_signature)
    template_prompt = template_prompt.replace('{PROJECT_LANGUAGE}',
                                              self.benchmark.language)

    prompt = self.llm.prompt_type()(None)
    prompt.add_priming(template_prompt)

    return prompt

  def _initial_refinement_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent for refinement."""
    last_result = results[-1]
    template_prompt = FUNCTION_REFINE_PROMPT
    template_prompt = template_prompt.replace('{FUNCTION_SIGNATURE}',
                                              self.benchmark.function_signature)
    template_prompt = template_prompt.replace('{PROJECT_LANGUAGE}',
                                              self.benchmark.language)
    template_prompt = template_prompt.replace(
        '{ERRORS}', json.dumps(last_result.chat_history))
    template_prompt = template_prompt.replace('{FUZZER_SOURCE_CODE}',
                                              last_result.fuzz_target_source)
    prompt = self.llm.prompt_type()(None)
    prompt.add_priming(template_prompt)

    return prompt

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, compiles: bool,
                           binary_exists: bool, referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = compiles
    if compile_process:
      build_result.compile_error = compile_process.stderr
      build_result.compile_log = self._format_bash_execution_result(
          compile_process)
    build_result.binary_exists = binary_exists
    build_result.is_function_referenced = referenced

  def _func_handler_run_get_source_code_of_function(self, tool_call, args):
    """Handles the 'get_source_code_of_function' tool call."""
    logger.info('Handling get_source_code_of_function: %s',
                args,
                trial=self.trial)
    function_signature = args['function_signature']
    if not function_signature:
      logger.error('Function signature is empty, cannot get source code.',
                   trial=self.trial)
      return False
    # Get the source code of the function.
    source_code = introspector.query_introspector_function_source(
        self.benchmark.project, function_signature)

    logger.info('Source code for function %s: %s',
                function_signature,
                source_code,
                trial=self.trial)
    # Extend messages to prepare for next iteration.
    self.new_llm_messages.append(tool_call)
    self.new_llm_messages.append({
        'type': 'function_call_output',
        'call_id': tool_call.call_id,
        'output': str(source_code)
    })

    return True

  def _func_handle_run_commands_in_container(self, tool_call, args):
    """Runs a command string in the project container."""

    # Execute the command directly, then return the formatted result
    commands = args['command']
    logger.info('LLM Requested commands: %s', commands, trial=self.trial)
    result = self.inspect_tool.execute(commands)
    prompt_text = self._format_bash_execution_result(result)

    # Extend messages to prepare for next iteration.
    self.new_llm_messages.append(tool_call)
    self.new_llm_messages.append({
        'type': 'function_call_output',
        'call_id': tool_call.call_id,
        'output': str(prompt_text)
    })
    return True

  def _func_handle_get_all_functions_in_project(self, tool_call, args):
    """Handles getting all functions in the project."""
    logger.info('Handling list_functions_in_project: %s',
                args,
                trial=self.trial)

    functions = introspector.query_introspector_all_signatures(
        self.benchmark.project)
    logger.info('Functions in project: %s', functions, trial=self.trial)
    # Extend messages to prepare for next iteration.
    self.new_llm_messages.append(tool_call)
    self.new_llm_messages.append({
        'type': 'function_call_output',
        'call_id': tool_call.call_id,
        'output': str(functions)
    })

  def _func_handler_run_harness_build(self, tool_call, args):
    """Tests the building of a fuzz harness source code."""
    logger.info('Handling test_fuzz_harness_build: %s', args, trial=self.trial)
    fuzzer_source_code = args['fuzzer_source_code']
    if not fuzzer_source_code:
      logger.error('Fuzzer source code is empty, cannot build.',
                   trial=self.trial)
      return False

    # Write the fuzzer source code to the container.
    self.inspect_tool.write_to_file(fuzzer_source_code,
                                    self.benchmark.target_path)

    # Compile the fuzzer source code.
    self.compile_result = self.inspect_tool.compile()
    compile_log = self._format_bash_execution_result(self.compile_result)

    if '<return code>\n0\n</return code>' in compile_log:
      logger.info('Fuzzer build succeeded', trial=self.trial)
      self.fuzzer_build_success = True
      self.fuzzer_source_code = fuzzer_source_code
    else:
      logger.info('Fuzzer build failed', trial=self.trial)

    logger.info('Compile result: %s', compile_log, trial=self.trial)

    # Extend messages to prepare for next iteration.
    self.new_llm_messages.append(tool_call)
    self.new_llm_messages.append({
        'type': 'function_call_output',
        'call_id': tool_call.call_id,
        'output': str(compile_log)
    })

    logger.info('Done compiling', trial=self.trial)
    return True

  def dispatch_tool_call(self, tool_call) -> int:
    """Dispatches the tool call to the appropriate function."""
    logger.info('#' * 20 + ' Tool call ' + '#' * 20, trial=self.trial)
    args = self._load_tool_arguments(tool_call)
    logger.info('Dispatching tool call: %s', tool_call.name, trial=self.trial)
    if args is not None:
      for arg in args:
        logger.info('Argument %s: %s', arg, args[arg], trial=self.trial)
    logger.info('#' * 51, trial=self.trial)
    time.sleep(5)

    if args is None:
      logger.error('Failed to load tool call arguments: %s',
                   tool_call.arguments,
                   trial=self.trial)
      return 0

    if tool_call.name == 'list_functions_in_project':
      self._func_handle_get_all_functions_in_project(tool_call, args)
      return 1
    if tool_call.name == 'run_commands_in_container':
      self._func_handle_run_commands_in_container(tool_call, args)
      return 1
    if tool_call.name == 'get_source_code_of_function':
      self._func_handler_run_get_source_code_of_function(tool_call, args)
      return 1
    if tool_call.name == 'test_fuzz_harness_build':
      self._func_handler_run_harness_build(tool_call, args)
      return 1
    return 0

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
    for function_tool in FUZZ_GEN_TOOLS:
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

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""

    self.fuzzer_build_success = False
    # Use keep to avoid deleting files, such as benchmark.yaml
    WorkDirs(self.args.work_dirs.base, keep=True)
    last_result = result_history[-1]
    logger.info('Executing %s', self.name, trial=last_result.trial)
    logger.info('Length of messages: %d',
                len(self.llm.messages),
                trial=last_result.trial)

    # Prepare for analysis
    self.compile_result = None
    benchmark = result_history[0].benchmark
    self.benchmark = benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})
    # If we have an analysis result, we should start a new prompt sequence
    # that refines the target.
    if isinstance(last_result, AnalysisResult):
      logger.info('Last result is AnalysisResult, will refine the target.',
                  trial=self.trial)
      # We expect this to be a Semantic Analysis result.
      prompt = self._initial_refinement_prompt(result_history)

      # Reset the LLM, we start from scratch here with a refined prompt.
      # This helps with context size etc.
      self.llm.messages = []
    else:
      logger.info('Last result is not AnalysisResult, will build a new target.',
                  trial=self.trial)
      # Starting from scratch, meaning there are no semantic results we can
      # use to refine a previously built target.
      prompt = self._initial_prompt(result_history)

    cur_round = 1
    counter = 0
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < self.max_round:
        logger.info('THIS ROUND: %02d, prompt: %s',
                    counter,
                    prompt.get(),
                    trial=self.trial)
        time.sleep(15)
        if counter > 20:
          logger.info('Counter is up, will exit', trial=self.trial)
          break
        counter += 1
        response = self.chat_llm_with_tools(client, prompt, FUZZ_GEN_TOOLS, 1)

        logger.info('LLM response for round %d: %s',
                    cur_round,
                    response,
                    trial=self.trial)

        # Execute all of the tool calls in the response.
        tools_analysed = 0
        self.new_llm_messages = []
        for tool_call in response.output:
          if tool_call.type != 'function_call':
            logger.info('Skipping non-function tool call: %s',
                        tool_call,
                        trial=-1)
            continue
          tools_analysed += self.dispatch_tool_call(tool_call)

        # If a correct fuzzing harness was built, we can stop execution.
        if self.fuzzer_build_success and self.compile_result is not None:
          logger.info('Fuzzer build succeeded, stopping execution.',
                      trial=self.trial)
          build_result.fuzz_target_source = self.fuzzer_source_code
          self._update_build_result(build_result,
                                    self.compile_result,
                                    compiles=True,
                                    binary_exists=True,
                                    referenced=True)
          return build_result

        # Prepare the prompt for the next round. There are two cases:
        # 1. If there are new messages from the LLM, we continue execution. This
        #    happens when there are no tool calls in the response.
        # 2. If there are no new messages, we tell the LLM we did not understand
        #    the commands.
        if len(self.new_llm_messages) > 0:
          logger.info('LLM has new messages, will continue execution.',
                      trial=self.trial)
          prompt = self.llm.prompt_type()(self.new_llm_messages)
        else:
          logger.info('No new messages from LLM, stopping execution.',
                      trial=self.trial)
          prompt = self.llm.prompt_type()(None)
          prompt.add_problem(
              'I was unable to interpret your last message. Use tool '
              'calls to direct this process instead of messages.')

        logger.info('Tool calls added: %d', tools_analysed, trial=self.trial)
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s',
                   self.inspect_tool.container_id,
                   trial=self.trial)
      self.inspect_tool.terminate()

    logger.info('Finished done', trial=self.trial)
    return build_result

