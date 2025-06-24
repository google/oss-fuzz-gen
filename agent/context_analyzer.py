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
"""
An LLM agent to analyze a function and identify its implicit requirements.
The results of this analysis will be used by the writer agents to
generate correct fuzz target for the function.
"""

import argparse
import os
from typing import Optional

import logger
import results as resultslib
from agent import base_agent
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder, prompts
from tool import container_tool


class ContextAnalyzer(base_agent.ADKBaseAgent):
  """An LLM agent to analyze the feasibility of crashes.
  """

  def __init__(self,
               trial: int,
               llm: models.LLM,
               args: argparse.Namespace,
               benchmark: benchmarklib.Benchmark,
               name: str = ''):

    builder = prompt_builder.ContextAnalyzerTemplateBuilder(llm, benchmark)

    description = builder.get_description().get()

    instruction = builder.get_instruction().get()

    tools = [self.get_function_implementation, self.search_project_files]

    super().__init__(trial, llm, args, benchmark, description, instruction,
                     tools, name)

    self.project_functions = None

  def write_requirements_to_file(self, args, requirements: str) -> str:
    """Write the requirements to a file."""
    if not requirements:
      logger.warning('No requirements to write to file.', trial=self.trial)
      return ''

    requirement_path = args.work_dirs.requirements_file_path(self.trial)

    with open(requirement_path, 'w') as f:
      f.write(requirements)

    logger.info('Requirements written to %s',
                requirement_path,
                trial=self.trial)

    return requirement_path

  def handle_llm_response(self, final_response_text: str,
                          result: resultslib.CrashFeasibilityResult) -> None:
    """Handle the LLM response and update the result."""

    result_str = self._parse_tag(final_response_text, 'response')
    conclusion = self._parse_tag(final_response_text, 'conclusion')
    if conclusion == 'False':
      result.feasible = False
    elif conclusion == 'True':
      result.feasible = True

    analysis = self._parse_tag(result_str, 'analysis')
    result.reason = analysis

    requirements = self._parse_tag(result_str, 'requirements')
    if requirements:
      # Write the requirements to a file
      self.write_requirements_to_file(self.args, result_str)

  def execute(self,
              result_history: list[resultslib.Result]) -> resultslib.Result:
    """Execute the agent with the given results."""

    WorkDirs(self.args.work_dirs.base, keep=True)
    logger.info('Executing %s', self.name, trial=self.trial)

    last_result = result_history[-1]

    if not isinstance(
        last_result, resultslib.AnalysisResult) or not last_result.crash_result:
      logger.error(
          f'Expected last result to be AnalysisResult, got {type(last_result)}.',
          trial=self.trial)
      return resultslib.Result(benchmark=self.benchmark,
                               trial=self.trial,
                               work_dirs=self.args.work_dirs)

    feasibility_result = resultslib.CrashFeasibilityResult()

    # Initialize the ProjectContainerTool for local file search
    self.inspect_tool = container_tool.ProjectContainerTool(self.benchmark)
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

    # Call the agent asynchronously and return the result
    prompt = self._initial_prompt(result_history)

    if not prompt or not prompt.get():
      logger.error('Failed to build initial prompt for FunctionAnalyzer.',
                   trial=self.trial)
      return resultslib.Result(benchmark=self.benchmark,
                               trial=self.trial,
                               work_dirs=self.args.work_dirs)

    final_response_text = self.chat_llm(self.round,
                                        client=None,
                                        prompt=prompt,
                                        trial=result_history[-1].trial)

    self.handle_llm_response(final_response_text, feasibility_result)

    self.inspect_tool.terminate()

    analysis_result = resultslib.AnalysisResult(
        author=self,
        run_result=last_result.run_result,
        crash_result=last_result.crash_result,
        feasibility_result=feasibility_result,
        chat_history={self.name: last_result.crash_result.to_dict()})

    return analysis_result

  def _initial_prompt(self, results: list[resultslib.Result]) -> prompts.Prompt:
    """Create the initial prompt for the agent."""

    last_result = results[-1]

    # Initialize the prompt builder
    builder = prompt_builder.ContextAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    if isinstance(last_result,
                  resultslib.AnalysisResult) and last_result.crash_result:
      function_requirements = self.get_function_requirements()
      prompt = builder.build_context_analysis_prompt(
          last_result, function_requirements, self.inspect_tool.tutorial(),
          self.inspect_tool.project_dir)
    else:
      logger.error(
          f'Unexpected result type {type(last_result)} '
          'or no last build result found.',
          trial=self.trial)
      prompt = prompts.TextPrompt()

    return prompt

  def search_project_files(self, request: str) -> str:
    """
    This function tool uses bash commands to search the project's source files,
      and retrieve requested code snippets or file contents.
    Args:
      request (str): The bash command to execute and its justification,
        formatted using the <reason> and <bash> tags.
    Returns:
      str: The response from executing the bash commands,
        formatted using the <bash>, <stdout> and <stderr> tags.
    """

    self.log_llm_response(request)

    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])

    if request:
      prompt = self._container_handle_bash_commands(request, self.inspect_tool,
                                                    prompt)

    # Finally check invalid request.
    if not request or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, 0, request, prompt)

    tool_response = prompt.get()

    self.log_llm_prompt(tool_response)

    return tool_response

  def get_function_implementation(self, project_name: str,
                                  function_name: str) -> str:
    """
    Retrieves a function's source from the fuzz introspector API,
      using the project's name and function's name

    Args:
        project_name (str): The name of the project.
        function_name (str): The name of the function.

    Returns:
        str: Source code of the function if found, otherwise an empty string.
    """
    request = f"""
      Requesting implementation for the function:
      Function name: {function_name}
      Project name: {project_name}
      """

    self.log_llm_response(request)

    if self.project_functions is None:
      logger.info(
          'Project functions not initialized. Initializing for project "%s".',
          project_name,
          trial=self.trial)
      functions_list = introspector.query_introspector_all_functions(
          project_name)

      if functions_list:
        self.project_functions = {
            func['debug_summary']['name']: func
            for func in functions_list
            if isinstance(func.get('debug_summary'), dict) and
            isinstance(func['debug_summary'].get('name'), str) and
            func['debug_summary']['name'].strip()
        }
      else:
        self.project_functions = None

    response = f"""
    Project name: {project_name}
    Function name: {function_name}
    """
    function_source = ''

    if self.project_functions:
      function_dict = self.project_functions.get(function_name, {})
      function_signature = function_dict.get('function_signature', '')

      function_source = introspector.query_introspector_function_source(
          project_name, function_signature)

    if function_source.strip():
      response += f"""
        Function source code:
        {function_source}
        """
    else:
      logger.error('Error: Function with name "%s" not found in project "%s".',
                   function_name,
                   project_name,
                   trial=self.trial)

    self.log_llm_prompt(response)

    return response
