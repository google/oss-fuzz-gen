
""" 
An LLM agent to analyze a function and identify its implicit requirements. 
The results of this analysis will be used by the writer agents to 
generate correct fuzz target for the function.
"""

import argparse
import asyncio

from typing import Optional

import logging
from agent.base_agent import BaseAgent
from data_prep import introspector
from experiment import benchmark as benchmarklib
from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt
from llm_toolkit import prompt_builder
from results import Result, PreWritingResult
from tool.base_tool import BaseTool

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types  # For creating message Content/Parts

# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
logger.addHandler(handler)


def get_function_source_tool(project_name: str, function_signature: str):

    """
    Retrieves a function's source using the project name and function signature.

    Args:
        project_name (str): The name of the project.
        function_signature (str): The signature of the function.
    
    Returns:
        str: The source code of the function if found, otherwise an empty string.
    """

    function_code = introspector.query_introspector_function_source(project_name, function_signature)

    if function_code:
        logger.info(f"Function with signature '{function_signature}' found and extracted.")
        return function_code
    else:
        logger.info(f"Error: Function with signature '{function_signature}' not found in project '{project_name}'.")
        return ""

class FunctionAnalyzer (BaseAgent):
    """An LLM agent to analyze a function and identify its implicit requirements.
    The results of this analysis will be used by the writer agents to 
    generate correct fuzz target for the function.
    """

    def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               tools: Optional[list[BaseTool]] = None,
               name: str = 'function_analyzer_agent',):

        # Call the parent constructor
        super().__init__(trial, llm, args, tools, name)

    def initialize(self, benchmark: benchmarklib.Benchmark):

        self.benchmark = benchmark

        # Initialize the prompt builder
        self.prompt_builder = prompt_builder.FunctionAnalyzerTemplateBuilder(self.llm, self.benchmark)

        # Get the agent's instructions
        analyzer_instruction = self.prompt_builder.build_instruction()

        # Create the agent using the ADK library
        function_analyzer = Agent(
            name=self.name,
            model='gemini-2.0-flash', #TODO: Get the model name from args. Currently, some of the default names are incompatible with the ADK library.
            description=("Agent to analyze a function and identify its implicit requirements."),
            instruction=analyzer_instruction.get(),
            tools=[get_function_source_tool]
        )

        # Get user id and session id
        # TODO: Figure out how to get this data
        user_id = "user"
        session_id = "session"

        # Create the session service
        session_service = InMemorySessionService()
        session = session_service.create_session(
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

        logger.info(f"Function Analyzer Agent created, with name: {self.name}, and session id: {session_id}")

    async def call_agent_async(self, query:str, runner, user_id:str, session_id:str) -> PreWritingResult:

        logger.info(f">>> User query: {query}")

        content = types.Content(role='user', parts=[types.Part(text=query)])

        final_response_text = "Agent did not produce a final response."

        result_available = False

        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content,
        ):
            if event.is_final_response():
                if event.content and event.content.parts:
                    final_response_text = event.content.parts[0].text
                    result_available = True
                elif event.actions and event.actions.escalate:
                    final_response_text = f"Agent escalated: {event.error_message or 'No specific message.'}"
                break

        logger.info(f"<<< Agent response: {final_response_text}")

        if result_available:
            # Get the requirements from the response
            requirements = self._parse_tags(final_response_text, 'requirement')
        else:
            requirements = []

        # Prepare the result
        result = PreWritingResult(
            benchmark=self.benchmark,
            trial=self.trial,
            work_dirs=self.args.work_dir,
            result_available=result_available,
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
        result = asyncio.run(self.call_agent_async(query, self.runner, user_id, session_id))

        if result.result_available:
            # Save the result to the history
            result_history.append(result)

            logger.info(f"Result available: {result.result_available}")
            logger.info(f"Requirements: {result.requirements}")
        return result

    def _initial_prompt(self, results: list[Result]) -> Prompt:
        """Create the initial prompt for the agent."""
    
        prompt = self.prompt_builder.build(project_name=self.benchmark.project, 
                                           function_signature=self.benchmark.function_signature)

        return prompt


        



    
    