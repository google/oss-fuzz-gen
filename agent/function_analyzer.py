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

import asyncio
import logging
from typing import Optional

from google.adk.agents import Agent, SequentialAgent, LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from agent.base_agent import BaseAgent
from experiment import benchmark as benchmarklib
from llm_toolkit import prompt_builder
from llm_toolkit.prompts import Prompt
from results import PreWritingResult, Result
from tool.fuzz_introspector_tool import FuzzIntrospectorTool

logger = logging.getLogger(__name__)


class FunctionAnalyzer(BaseAgent):
  """An LLM agent to analyze a function and identify its implicit requirements.
  The results of this analysis will be used by the writer agents to
  generate correct fuzz target for the function.
  """

  def initialize(self, benchmark: benchmarklib.Benchmark):
    """Initialize the function analyzer agent with the given benchmark."""

    self.benchmark = benchmark

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    # Initialize the Fuzz Introspector tool
    introspector_tool = FuzzIntrospectorTool(benchmark, self.name)

    context_retriever = LlmAgent(
        name="ContextRetrieverAgent",
        model='gemini-2.0-flash',
        description=(
            "Retrieves the implementation of a function and its children from Fuzz Introspector."),
        instruction=builder.build_context_retriever_instruction().get(),
        tools=[introspector_tool._function_source_with_signature, introspector_tool._function_source_with_name],
        generate_content_config=types.GenerateContentConfig(
        temperature=0.0,),
        output_key="FUNCTION_SOURCE",
    )

    # Create the agent using the ADK library
    requirements_extractor = LlmAgent(
        name="RequirementsExtractorAgent",
        # TODO: Get the model name from args.
        # Currently, the default names are incompatible with the ADK library.
        model='gemini-2.0-flash',
        description=(
            "Extracts a function's requirements from its source implementation."),
        instruction=builder.build_instruction().get(),
        output_key="FUNCTION_REQUIREMENTS",
    )

    # Create the function analyzer agent
    function_analyzer = SequentialAgent(
        name="FunctionAnalyzerAgent",
        sub_agents=[context_retriever, requirements_extractor],
        description=(
            "Sequential agent to retrieve a function's source, analyze it and extract its requirements."),
    )

    # Get user id and session id
    # TODO: Figure out how to get this data
    user_id = "user"
    session_id = "session"

    # Create the session service
    session_service = InMemorySessionService()
    session_service.create_session(
        app_name=self.name,
        user_id=user_id,
        session_id=session_id,
    )

    # Create the runner
    self.runner = Runner(
        agent=function_analyzer,
        app_name=self.name,
        session_service=session_service,
    )

    logger.info(
        "Function Analyzer Agent created, with name: %s, and session id: %s",
        self.name, session_id)

  async def call_agent(self, query: str, runner: Runner, user_id: str,
                 session_id: str) -> PreWritingResult:
    """Call the agent asynchronously with the given query."""

    logger.info(">>> User query: %s", query)

    content = types.Content(role='user', parts=[types.Part(text=query)])

    final_response_text = "Agent did not produce a final response."

    result_available = False

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=content,
    ):

      logger.info("Event is %s", event.content)
      if event.is_final_response():
        if event.content and event.content.parts and event.content.parts[0].text:
          final_response_text = event.content.parts[0].text
          result_available = True
        elif event.actions and event.actions.escalate:
          error_message = event.error_message
          logger.error(f"Agent escalated: %s", error_message)

    logger.info("<<< Agent response: %s", final_response_text)

    if result_available and self._parse_tag(final_response_text, 'response'):
      # Get the requirements from the response
      requirements = self._parse_tags(final_response_text, 'requirement')
      result_raw = self._parse_tag(final_response_text, 'response')
    else:
      requirements = []
      result_raw = ''

    # Prepare the result
    result = PreWritingResult(
        benchmark=self.benchmark,
        trial=self.trial,
        work_dirs=self.args.work_dir,
        result_available=result_available,
        result_raw=result_raw,
        requirements=requirements,
    )

    return result

  def execute(self, result_history: list[Result]) -> PreWritingResult:
    """Execute the agent with the given results."""

    # Call the agent asynchronously and return the result
    prompt = self._initial_prompt(result_history)
    query = prompt.gettext()
    user_id = "user"
    session_id = "session"
    result = asyncio.run(self.call_agent(query, self.runner, user_id, session_id))

    if result and result.result_available:
      # Save the result to the history
      result_history.append(result)

    return result

  def _initial_prompt(self, results: Optional[list[Result]] = None) -> Prompt:
    """Create the initial prompt for the agent."""

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    prompt = builder.build_prompt()

    return prompt
