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
import asyncio
import os
from typing import Optional

from google.adk import agents, runners, sessions
from google.genai import types

import logger
import results as resultslib
from agent import base_agent
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder, prompts
from tool import base_tool, container_tool, fuzz_introspector_tool


class FunctionAnalyzer(base_agent.ADKBaseAgent):
  """An LLM agent to analyze a function and identify its implicit requirements.
  The results of this analysis will be used by the writer agents to
  generate correct fuzz target for the function.
  """

  def __init__(self,
               trial: int,
               llm: models.LLM,
               args: argparse.Namespace,
               benchmark: benchmarklib.Benchmark,\
               name: str = ''):

    description = """
    Extracts a function's requirements
    from its source implementation.
    """
    instruction = """
    You are a security engineer tasked with analyzing a function
    and extracting its input requirements,
    necessary for it to execute correctly.
    """

    tools = [self.get_function_implementation, self.search_project_files]

    super().__init__(trial, llm, args, benchmark, description, instruction,
                     tools)

  def write_requirements_to_file(self, args, requirements: str) -> str:
    """Write the requirements to a file."""
    if not requirements:
      logger.warning("No requirements to write to file.", trial=self.trial)
      return ''

    requirement_path = os.path.join(args.work_dirs.requirements,
                                    f"{self.benchmark.id}.txt")

    with open(requirement_path, 'w') as f:
      f.write(requirements)

    logger.info("Requirements written to %s",
                requirement_path,
                trial=self.trial)

    return requirement_path

  def handle_llm_response(self, final_response_text: str,
                          result: resultslib.Result) -> None:
    """Handle the LLM response and update the result."""

    result_str = self._parse_tag(final_response_text, 'response')
    requirements = self._parse_tag(result_str, 'requirements')
    if requirements:
      # Write the requirements to a file
      requirement_path = self.write_requirements_to_file(self.args, result_str)
      function_analysis = resultslib.FunctionAnalysisResult(requirement_path)
      result.function_analysis = function_analysis

  def execute(self,
              result_history: list[resultslib.Result]) -> resultslib.Result:
    """Execute the agent with the given results."""

    WorkDirs(self.args.work_dirs.base, keep=True)
    logger.info('Executing %s', self.name, trial=self.trial)

    result = resultslib.Result(
        benchmark=self.benchmark,
        trial=self.trial,
        work_dirs=self.args.work_dirs,
    )

    cur_round = 1

    # Call the agent asynchronously and return the result
    prompt = self._initial_prompt(result_history)
    # Initialize the ProjectContainerTool for local file search
    self.inspect_tool = container_tool.ProjectContainerTool(self.benchmark)
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

    final_response_text = self.chat_llm(cur_round,
                                        client=None,
                                        prompt=prompt,
                                        trial=result_history[-1].trial)

    self.handle_llm_response(final_response_text, result)

    self.inspect_tool.terminate()

    return result

  def _initial_prompt(
      self,
      results: Optional[list[resultslib.Result]] = None) -> prompts.Prompt:
    """Create the initial prompt for the agent."""

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    prompt = builder.build_prompt()

    prompt.append(self.inspect_tool.tutorial())

    return prompt

  def search_project_files(self, request: str) -> str:
    """
    This function tool uses bash commands to search the project's source files,
      and retrieve requested code snippets or file contents.
    Args:
      request (str): The bash command to execute and its justification, formatted using the <reason> and <bash> tags.
    Returns:
      str: The response from executing the bash commands, formatted using the <bash>, <stdout> and <stderr> tags.
    """

    logger.info('<CHAT PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
                self.round,
                request,
                self.round,
                trial=self.trial)

    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])

    if request:
      prompt = self._container_handle_bash_commands(request, self.inspect_tool,
                                                    prompt)

    # Finally check invalid request.
    if not request or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, 0, request, prompt)

    response = prompt.get()

    # TODO(pamusuo): Move this logging to ADKBaseAgent.
    self.round += 1
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                self.round,
                response,
                self.round,
                trial=self.trial)

    return response

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
    Retrieve the source code of the function '{function_name}' from the project '{project_name}'.
    """

    logger.info('<CHAT PROMPT:ROUND %02d> %s </CHAT PROMPT:ROUND %02d>',
                self.round,
                request,
                self.round,
                trial=self.trial)

    if self.project_functions is None:
      logger.info(
          "Project functions not initialized. Initializing for project '%s'.",
          project_name,
          trial=self.trial)
      functions_list = introspector.query_introspector_all_functions(
          project_name)

      if functions_list:
        self.project_functions = {
            func["debug_summary"]["name"]: func
            for func in functions_list
            if "debug_summary" in func and "name" in func["debug_summary"]
        }
      else:
        self.project_functions = None

    if (self.project_functions is None or
        function_name not in self.project_functions):
      logger.error("Error: Required function not found for project '%s'.",
                   project_name,
                   trial=self.trial)
      return ""

    function_signature = self.project_functions[function_name][
        "function_signature"]

    function_source = introspector.query_introspector_function_source(
        project_name, function_signature)

    self.round += 1
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                self.round,
                function_source,
                self.round,
                trial=self.trial)

    return function_source
