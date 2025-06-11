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
from experiment import benchmark as benchmarklib
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder, prompts
from tool import base_tool, fuzz_introspector_tool


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

    description="""
    Extracts a function's requirements
    from its source implementation.
    """
    instruction= """
    You are a security engineer tasked with analyzing a function
    and extracting its input requirements,
    necessary for it to execute correctly.
    """

    introspector_tool = fuzz_introspector_tool.FuzzIntrospectorTool(
        self.benchmark, self.name)
    tools = [introspector_tool.function_source_with_name]

    super().__init__(trial, llm, args, benchmark, description, instruction, tools)


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

  def handle_llm_response(
      self, final_response_text: str,
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

    final_response_text = self.chat_llm(cur_round,
                                 client=None,
                                 prompt=prompt,
                                 trial=result_history[-1].trial)

    self.handle_llm_response(final_response_text, result)

    return result

  def _initial_prompt(
      self,
      results: Optional[list[resultslib.Result]] = None) -> prompts.Prompt:
    """Create the initial prompt for the agent."""

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    prompt = builder.build_prompt()

    return prompt
