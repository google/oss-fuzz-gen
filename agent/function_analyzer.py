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
import logging
import os
from typing import Optional

from google.adk import agents, runners, sessions
from google.genai import types

from experiment.workdir import WorkDirs
import results as resultslib
from agent import base_agent
from experiment import benchmark as benchmarklib
from llm_toolkit import models, prompt_builder, prompts
from tool import base_tool, fuzz_introspector_tool

logger = logging.getLogger(__name__)


class FunctionAnalyzer(base_agent.BaseAgent):
  """An LLM agent to analyze a function and identify its implicit requirements.
  The results of this analysis will be used by the writer agents to
  generate correct fuzz target for the function.
  """

  def __init__(self,
               trial: int,
               llm: models.LLM,
               args: argparse.Namespace,
               tools: Optional[list[base_tool.BaseTool]] = None,
               name: str = ''):

    # Ensure the llm is an instance of VertexAIModel
    if not isinstance(llm, models.VertexAIModel):
      raise ValueError(
          "FunctionAnalyzer agent requires a VertexAIModel instance for llm.")

    self.vertex_ai_model = llm._vertex_ai_model

    super().__init__(trial, llm, args, tools, name)

  def initialize(self, benchmark: benchmarklib.Benchmark):
    """Initialize the function analyzer agent with the given benchmark."""

    self.benchmark = benchmark

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    # Initialize the Fuzz Introspector tool
    introspector_tool = fuzz_introspector_tool.FuzzIntrospectorTool(
        benchmark, self.name)

    # Create the agent using the ADK library
    # TODO(pamusuo): Create another AdkBaseAgent that extends BaseAgent and initializes an ADK agent as well.
    function_analyzer = agents.LlmAgent(
        name="FunctionAnalyzer",
        model=self.vertex_ai_model,
        description="""Extracts a function's requirements
                        from its source implementation.""",
        instruction="""You are a security engineer tasked with analyzing a function
        and extracting its input requirements, necessary for it to execute correctly.""",
        tools=[
            introspector_tool.function_source_with_name
        ],
    )

    # Create the session service
    session_service = sessions.InMemorySessionService()
    session_service.create_session(
        app_name=self.name,
        user_id="user",
        session_id=f"session_{self.trial}",
    )

    # Create the runner
    self.runner = runners.Runner(
        agent=function_analyzer,
        app_name=self.name,
        session_service=session_service,
    )

    logger.info("Function Analyzer Agent created, with name: %s", self.name)

  async def call_agent(self, query: str, runner: runners.Runner, user_id: str,
                       session_id: str) -> str:
    """Call the agent asynchronously with the given query."""

    content = types.Content(role='user', parts=[types.Part(text=query)])

    final_response_text = ''

    result_available = False

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=content,
    ):

      if event.is_final_response():
        if (event.content and event.content.parts and
            event.content.parts[0].text):
          final_response_text = event.content.parts[0].text
          result_available = True
        elif event.actions and event.actions.escalate:
          error_message = event.error_message
          logger.error("Agent escalated: %s", error_message)

    logger.info("<<< Agent response: %s", final_response_text)

    if result_available and self._parse_tag(final_response_text, 'response'):
      # Get the requirements from the response
      result_str = self._parse_tag(final_response_text, 'response')
    else:
      result_str = ''

    return result_str

  def write_requirements_to_file(self, args, requirements: str) -> str:
    """Write the requirements to a file."""
    if not requirements:
      logger.warning("No requirements to write to file.")
      return ''

    requirement_path = os.path.join(
        args.work_dirs.requirements,
        f"{self.benchmark.id}.txt")

    with open(requirement_path, 'w') as f:
      f.write(requirements)

    logger.info("Requirements written to %s", requirement_path)

    return requirement_path

  def execute(
      self,
      result_history: list[resultslib.Result]) -> resultslib.Result:
    """Execute the agent with the given results."""

    WorkDirs(self.args.work_dirs.base, keep=True)

    # Call the agent asynchronously and return the result
    prompt = self._initial_prompt(result_history)
    query = prompt.gettext()

    # Validate query is not empty
    if not query.strip():
      raise ValueError("Query is empty. Cannot call the agent.")

    user_id = "user"
    session_id = f"session_{self.trial}"
    result_str = asyncio.run(
        self.call_agent(query, self.runner, user_id, session_id))

    if result_str:
      # Write the requirements to a file
      requirement_path = self.write_requirements_to_file(
          self.args, result_str)
      function_analysis = resultslib.FunctionAnalysisResult(requirement_path)
    else:
      function_analysis = None

    result = resultslib.Result(
        benchmark=self.benchmark,
        trial=self.trial,
        work_dirs=self.args.work_dirs,
        function_analysis=function_analysis,
    )

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
