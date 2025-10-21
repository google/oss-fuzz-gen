"""
An LLM agent to analyze a function and identify its implicit requirements.
The results of this analysis will be used by the writer agents to
generate correct fuzz target for the function.
"""

import argparse
from typing import Optional

from google.adk.tools import ToolContext

import logger
import results as resultslib
from agent_graph.agents import base_agent
from agent_graph.agents.langgraph_agent import LangGraphAgent
from data_prep import introspector
from experiment import benchmark as benchmarklib
from experiment.workdir import WorkDirs
from llm_toolkit import models, prompt_builder, prompts
from tool import container_tool

class FunctionAnalyzer(LangGraphAgent):
  """An LLM agent to analyze a function and identify its implicit requirements.
  The results of this analysis will be used by the writer agents to
  generate correct fuzz target for the function.
  """

  def __init__(self,
               trial: int,
               llm: models.LLM,
               args: argparse.Namespace,
               benchmark: benchmarklib.Benchmark,
               name: str = ''):

    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(llm, benchmark)

    description = builder.get_description().get()

    instruction = builder.get_instruction().get()

    tools = [
        self.get_function_implementation, self.search_project_files,
        self.return_final_result
    ]

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

  def handle_llm_response(
      self, function_analysis_result: resultslib.FunctionAnalysisResult,
      result: resultslib.Result) -> None:
    """Handle the LLM response and update the result."""

    function_requirements_text = self.get_xml_representation(
        function_analysis_result.to_dict())

    # Write the requirements to a file
    requirement_path = self.write_requirements_to_file(
        self.args, function_requirements_text)
    function_analysis_result.function_analysis_path = requirement_path
    result.function_analysis = function_analysis_result

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

    # Initialize the ProjectContainerTool for local file search
    self.inspect_tool = container_tool.ProjectContainerTool(self.benchmark)
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')

    # Call the agent asynchronously and return the result
    prompt = self._initial_prompt(result_history)

    cur_round = 1
    while cur_round <= self.max_round:
      # Get the appropriate client for the LLM
      client = None
      if hasattr(self.llm, '_get_client'):
        client = self.llm._get_client()
      
      final_response = self.chat_llm(cur_round,
                                     client=client,
                                     prompt=prompt,
                                     trial=result_history[-1].trial)

      function_analyzer_result = resultslib.FunctionAnalysisResult.from_dict(
          final_response)
      if function_analyzer_result:
        self.handle_llm_response(function_analyzer_result, result)
        break

      # Handle invalid LLM response
      template_builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
          self.llm, self.benchmark)

      prompt = self._container_handle_invalid_tool_usage(
          [self.inspect_tool], cur_round, final_response,
          template_builder.build(), template_builder.get_response_format())
      
      cur_round += 1

    self.inspect_tool.terminate()
    
    # Finalize logging when agent completes
    self.finalize()
    
    return result

  def _initial_prompt(
      self,
      results: Optional[list[resultslib.Result]] = None) -> prompts.Prompt:
    """Create the initial prompt for the agent."""

    # Initialize the prompt builder
    builder = prompt_builder.FunctionAnalyzerTemplateBuilder(
        self.llm, self.benchmark)

    prompt = builder.build_prompt(self.inspect_tool.project_dir)

    prompt.append(self.inspect_tool.tutorial())

    # Log the initial prompt using unified logging
    self.log_llm_prompt(prompt.get())

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

    # Log tool request (but don't spam logs with every bash command)
    if len(request) > 50:  # Only log substantial requests
      self.log_llm_response(f"TOOL_REQUEST: {request[:200]}...")
    else:
      self.log_llm_response(f"TOOL_REQUEST: {request}")

    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])

    if request:
      prompt = self._container_handle_bash_commands(request, self.inspect_tool,
                                                    prompt)

    # Finally check invalid request.
    if not request or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage([self.inspect_tool], 0,
                                                         request, prompt)

    tool_response = prompt.get()

    # Log tool response summary (avoid massive outputs)
    if len(tool_response) > 500:
      self.log_llm_response(f"TOOL_RESPONSE: {tool_response[:300]}...")
    else:
      self.log_llm_response(f"TOOL_RESPONSE: {tool_response}")

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

    # Log function implementation request
    self.log_llm_response(f"FUNCTION_REQUEST: {function_name} from {project_name}")

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

    # Log function implementation response summary
    if function_source.strip():
      self.log_llm_response(f"FUNCTION_FOUND: {function_name} ({len(function_source)} chars)")
    else:
      self.log_llm_response(f"FUNCTION_NOT_FOUND: {function_name} in {project_name}")

    return response

  def return_final_result(self, project_name: str, function_signature: str,
                          description: str, requirements: str,
                          tool_context: ToolContext) -> dict:
    """
    Provide final analysis results, including a detailed description of the function and requirements on its input and global variables.

    Args:
        project_name (str): The name of the project.
        function_signature (str): The signature of the function you were provided.
        description (str): A detailed description of the function.
        requirements (str): Requirements on the function's input and global variables, formatted using <requirement> tags.

    Returns:
        This function does not return anything.
    """

    function_analysis = resultslib.FunctionAnalysisResult(
        description=description,
        function_signature=function_signature,
        project_name=project_name,
        requirements=requirements,
    )

    # We have received final result. Instruct the agent to terminate execution.
    # tool_context._invocation_context.end_invocation = True
    self.end_llm_chat(tool_context)
    return function_analysis.to_dict()
