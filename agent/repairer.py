"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import re
import subprocess as sp
import time
from datetime import timedelta
from typing import Optional

from vertexai.preview.generative_models import (ChatSession, FunctionCall,
                                                FunctionDeclaration,
                                                GenerationResponse, Part, Tool,
                                                ToolConfig)

import logger
from agent.base_agent import BaseAgent
from experiment.benchmark import Benchmark
from llm_toolkit.prompt_builder import (DefaultTemplateBuilder,
                                        RepairerTemplateBuilder)
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.base_tool import BaseTool
from tool.container_tool import ProjectContainerTool

MAX_ROUND = 100


class Repairer(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    benchmark = results[-1].benchmark
    assert isinstance(results[-1], BuildResult)
    prompt_builder = RepairerTemplateBuilder(
        model=self.llm,
        benchmark=benchmark,
        build_result=results[-1],
    )
    prompt = prompt_builder.build(example_pair=[])
    self.protocol = (
        'Use the inspect_code_or_conclude_fuzz_target tool to inspect code or '
        'the  submit the fuzz target and build script')
    return prompt

  def _update_fuzz_target_and_build_script(self, cur_round: int,
                                           fuzz_target_source: str,
                                           build_script_source: str,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    build_result.fuzz_target_source = fuzz_target_source
    if fuzz_target_source:
      logger.debug('ROUND %02d Parsed fuzz target from LLM:\n%s', cur_round,
                   fuzz_target_source)
    else:
      logger.error('ROUND %02d No fuzz target source code in conclusion.',
                   cur_round)

    if build_script_source:
      logger.debug('ROUND %02d Parsed build script from LLM:\n%s', cur_round,
                   build_script_source)
    else:
      logger.debug('ROUND %02d No build script in conclusion.', cur_round)

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, status: bool,
                           referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = status
    build_result.compile_error = compile_process.stderr
    build_result.compile_log = self._format_bash_execution_result(
        compile_process)
    # Remove the compile command, e.g., <bash>compile</bash>
    build_result.compile_log = re.sub(r'<bash>.*?</bash>',
                                      '',
                                      build_result.compile_log,
                                      flags=re.DOTALL)
    build_result.is_function_referenced = referenced

  def _validate_fuzz_target_and_build_script(self, cur_round: int,
                                             build_result: BuildResult) -> None:
    """Validates the new fuzz target and build script."""
    # Steps:
    #   1. Recompile without modifying the build script, in case LLM is wrong.
    #   2. Recompile with the modified build script, if any.
    build_script_source = build_result.build_script_source

    logger.info('First compile fuzz target without modifying build script.')
    build_result.build_script_source = ''
    self._validate_fuzz_target_and_build_script_via_compile(
        cur_round, build_result)

    if not build_result.success and build_script_source:
      logger.info('Then compile fuzz target with modified build script.')
      build_result.build_script_source = build_script_source
      self._validate_fuzz_target_and_build_script_via_compile(
          cur_round, build_result)

  def _validate_fuzz_target_references_function(
      self, compilation_tool: ProjectContainerTool, benchmark: Benchmark,
      cur_round: int) -> bool:
    """Validates if the LLM generated fuzz target assembly code references
    function-under-test."""
    disassemble_result = compilation_tool.execute(
        'objdump --disassemble=LLVMFuzzerTestOneInput -d '
        f'/out/{benchmark.target_name}')
    function_referenced = (disassemble_result.returncode == 0 and
                           benchmark.function_name in disassemble_result.stdout)
    logger.debug('ROUND %02d Final fuzz target function referenced: %s',
                 cur_round, function_referenced)
    if not function_referenced:
      logger.debug('ROUND %02d Final fuzz target function not referenced',
                   cur_round)
    return function_referenced

  def _validate_fuzz_target_and_build_script_via_compile(
      self, cur_round: int, build_result: BuildResult) -> None:
    """Validates the new fuzz target and build script by recompiling them."""
    benchmark = build_result.benchmark
    compilation_tool = ProjectContainerTool(benchmark=benchmark)

    # Replace fuzz target and build script in the container.
    replace_file_content_command = (
        'cat << "EOF" > {file_path}\n{file_content}\nEOF')
    compilation_tool.execute(
        replace_file_content_command.format(
            file_path=benchmark.target_path,
            file_content=build_result.fuzz_target_source))

    if build_result.build_script_source:
      compilation_tool.execute(
          replace_file_content_command.format(
              file_path='/src/build.sh',
              file_content=build_result.build_script_source))

    # Recompile.
    logger.info('===== ROUND %02d Recompile =====', cur_round)
    start_time = time.time()
    compile_process = compilation_tool.compile()
    end_time = time.time()
    logger.debug('ROUND %02d compilation time: %s', cur_round,
                 timedelta(seconds=end_time - start_time))
    compile_succeed = compile_process.returncode == 0
    logger.debug('ROUND %02d Fuzz target compiles: %s', cur_round,
                 compile_succeed)

    # Double-check binary.
    ls_result = compilation_tool.execute(f'ls /out/{benchmark.target_name}')
    binary_exists = ls_result.returncode == 0
    logger.debug('ROUND %02d Final fuzz target binary exists: %s', cur_round,
                 binary_exists)

    # Validate if function-under-test is referenced by the fuzz target.
    function_referenced = self._validate_fuzz_target_references_function(
        compilation_tool, benchmark, cur_round)

    compilation_tool.terminate()
    self._update_build_result(build_result,
                              compile_process=compile_process,
                              status=compile_succeed and binary_exists,
                              referenced=function_referenced)

  def _submit_conclusion(self, cur_round: int, params: dict[str, str],
                         build_result: BuildResult,
                         result_parts: list[Part]) -> Optional[dict[str, str]]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    logger.info('----- ROUND %02d Received conclusion -----', cur_round)

    fuzz_target_source = params.get('fuzz_target', '')
    build_script_source = params.get('build_script', '')
    self._update_fuzz_target_and_build_script(cur_round, fuzz_target_source,
                                              build_script_source, build_result)

    self._validate_fuzz_target_and_build_script(cur_round, build_result)
    if build_result.success:
      logger.info('***** Repairer succeeded in %02d rounds *****', cur_round)
      return None

    if not build_result.compiles:
      compile_log = self.llm.truncate_prompt(
          build_result.compile_log,
          extra_text='\n'.join(
              str(part.function_response) for part in result_parts)).strip()
      logger.info('***** Failed to recompile in %02d rounds *****', cur_round)
      content = params | {
          'build result': compile_log,
      }
    elif not build_result.is_function_referenced:
      logger.info(
          '***** Fuzz target does not reference function-under-test in %02d '
          'rounds *****', cur_round)
      not_referenced_text = (
          'The fuzz target builds successfully, but the target function '
          f'`{build_result.benchmark.function_signature}` was not used by '
          '`LLVMFuzzerTestOneInput` in fuzz target. YOU MUST CALL FUNCTION '
          f'`{build_result.benchmark.function_signature}` INSIDE FUNCTION '
          '`LLVMFuzzerTestOneInput`.')
      content = params | {
          'build result': not_referenced_text,
      }
    else:
      prompt_text = 'This should never happen.'
      content = params | {
          'build result': prompt_text,
      }

    return content

  def _execute_bash_command(self, params: dict[str, str]) -> dict[str, str]:
    """Handles the command from LLM with container |tool|."""
    command = params.get('command', '')
    process = self.inspect_tool.execute(command)
    stdout = self.llm.truncate_prompt(process.stdout)
    stderr = self.llm.truncate_prompt(process.stderr, stdout)
    return params | {
        'command': process.args,
        'return code': str(process.returncode),
        'stdout': stdout,
        'stderr': stderr,
    }

  def invalid_function_usage(self, cur_round: int, call: FunctionCall) -> Part:
    """Formats a prompt to re-teach LLM how to use the |tool|."""
    logger.warning('ROUND %02d Invalid response from LLM: %s', cur_round, call)
    prompt_text = (f'Invalid function call (call), Please follow the system '
                   f'instructions:\n{self.protocol}')
    return Part.from_function_response(name=call.name,
                                       response={'content': prompt_text})

  def call_function(self, cur_round: int, call: FunctionCall,
                    build_result: BuildResult,
                    results: list[Part]) -> Optional[Part]:
    """Calls tool functions based on LLM response."""
    args = dict(call.args)
    if call.name != 'inspect_code_or_conclude_fuzz_target':
      return Part.from_function_response(
          name=call.name,
          response={
              'content':
                  args | {
                      'error':
                          ('Malformatted function calls, function name is not '
                           f'{call.name}')
                  },
          })

    content = {}
    for name in args.keys():
      params = args.get(name, {})
      if name == 'inspect':
        content[name] = self._execute_bash_command(params)
      if name == 'conclude':
        build_feedback = self._submit_conclusion(cur_round, params,
                                                 build_result, results)
        if build_feedback is None:
          return None
        content[name] = build_feedback

      if content.get(name) is None:
        content[name] = {
            name:
                params | {
                    'error':
                        f'Malformatted function calls, no feature name: {name}.'
                }
        }

    return Part.from_function_response(
        name='inspect_code_or_conclude_fuzz_target',
        response={'content': content})

  def _container_tool_reaction(self, cur_round: int,
                               response: GenerationResponse,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    results = []
    for call in response.candidates[0].function_calls:
      result = self.call_function(cur_round, call, build_result, results)
      results.append(result)
    return DefaultTemplateBuilder(self.llm, initial=results).build([])

  def _initialize_chat_session(self, tools: list[BaseTool]) -> ChatSession:
    """Initializes the LLM chat session with |tools|"""
    functions = [
        FunctionDeclaration(
            name='inspect_code_or_conclude_fuzz_target',
            description=
            ('Inspect source code and environment variables with parameters `reason` and `command` or conclude the revised fuzz target generation result with parameters `summary`, `fuzz_target`, and `build_script`. '
            ),
            parameters={
                'type': 'object',
                'properties': {
                    'inspect': {
                        'type': 'object',
                        'properties': {
                            'reason': {
                                'type':
                                    'string',
                                'description': (
                                    'The reason to execute the command. E.g., Inspect and '
                                    'learn from all existing human written fuzz targets as '
                                    'examples.')
                            },
                            'command': {
                                'type':
                                    'string',
                                'description': (
                                    'The bash command to execute. E.g., grep -rlZ '
                                    '"LLVMFuzzerTestOneInput(" "$(dirname {FUZZ_TARGET_PATH})"'
                                    ' | xargs -0 cat')
                            }
                        },
                        'required': ['reason', 'command']
                    },
                    'conclude': {
                        'type': 'object',
                        'properties': {
                            'summary': {
                                'type':
                                    'string',
                                'description': (
                                    'The reason to execute the command. E.g., Inspect and '
                                    'learn from all existing human written fuzz targets as '
                                    'examples.')
                            },
                            'fuzz_target': {
                                'type':
                                    'string',
                                'description': (
                                    'The revised fuzz target in full. Do not omit any '
                                    'code even if it is the same as the previous one.'
                                )
                            },
                            'build_script': {
                                'type':
                                    'string',
                                'description': (
                                    'The full build script if different from the '
                                    'existing one. Do not omit any code even if it is '
                                    'the same as the previous one.')
                            }
                        },
                        'required': ['summary', 'fuzz_target', 'build_script']
                    }
                },
            },
        ),
    ]
    self.llm.tools = [Tool(function_declarations=[func]) for func in functions]
    self.llm.tool_config = ToolConfig(
        function_calling_config=ToolConfig.FunctionCallingConfig(
            mode=ToolConfig.FunctionCallingConfig.Mode.ANY))
    model = self.llm.get_model()
    logger.info('Tools: %s', model._tools)
    return self.llm.get_chat_client(model=model)

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    logger.info('Executing Repairer')
    last_result = result_history[-1]
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    cur_round = 1
    build_result = result_history[-1]
    assert isinstance(build_result, BuildResult)
    prompt = self._initial_prompt(result_history)
    try:
      client = self._initialize_chat_session([self.inspect_tool])
      while prompt and cur_round < MAX_ROUND:
        response = self.chat_llm(cur_round, client=client, prompt=prompt)
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)
        cur_round += 1
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s',
                   self.inspect_tool.container_id)
      self.inspect_tool.terminate()
    return build_result
