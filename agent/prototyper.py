"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import subprocess as sp
import time
from datetime import timedelta
from typing import Optional

from vertexai.preview.generative_models import (ChatSession, FunctionCall,
                                                GenerationResponse, Part, Tool,
                                                ToolConfig)

import logger
from agent.base_agent import BaseAgent
from data_prep.project_context.context_introspector import ContextRetriever
from experiment.benchmark import Benchmark
from llm_toolkit.prompt_builder import (DefaultTemplateBuilder,
                                        PrototyperTemplateBuilder)
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.container_tool import ProjectContainerTool

MAX_ROUND = 100


class Prototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    benchmark = results[-1].benchmark
    retriever = ContextRetriever(benchmark)
    context_info = retriever.get_context_info()
    prompt_builder = PrototyperTemplateBuilder(
        model=self.llm,
        benchmark=benchmark,
    )
    prompt = prompt_builder.build(example_pair=[],
                                  project_context_content=context_info)
    # prompt = prompt_builder.build(example_pair=EXAMPLE_FUZZ_TARGETS.get(
    #     benchmark.language, []),
    #                               tool_guides=self.inspect_tool.tutorial())
    return prompt

  def _initialize_chat_session(self) -> ChatSession:
    """Initializes the LLM chat session with |tools|"""
    self.llm.tools = [
        Tool(function_declarations=self.inspect_tool.declarations())
    ]
    self.llm.tool_config = ToolConfig(
        function_calling_config=ToolConfig.FunctionCallingConfig(
            mode=ToolConfig.FunctionCallingConfig.Mode.ANY))
    model = self.llm.get_model()
    return self.llm.get_chat_client(model=model)

  def _update_fuzz_target_and_build_script(self, cur_round: int, args: dict,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    fuzz_target_source = self._filter_code(args.get('fuzz_target', ''))
    build_result.fuzz_target_source = fuzz_target_source

    args['fuzz_target'] = fuzz_target_source
    if fuzz_target_source:
      logger.debug('ROUND %02d Parsed fuzz target from LLM: %s',
                   cur_round,
                   fuzz_target_source,
                   trial=build_result.trial)
    else:
      logger.error('ROUND %02d No fuzz target source code in conclusion: %s',
                   cur_round,
                   args,
                   trial=build_result.trial)

    build_script_source = self._filter_code(args.get('build_script', ''))
    args['build_script'] = build_script_source
    if build_script_source:
      logger.debug('ROUND %02d Parsed build script from LLM: %s',
                   cur_round,
                   build_script_source,
                   trial=build_result.trial)
    else:
      logger.debug('ROUND %02d No build script in conclusion: %s',
                   cur_round,
                   args,
                   trial=build_result.trial)

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, status: bool,
                           referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = status

    compile_result = self._format_bash_execution_result(compile_process)
    build_result.compile_stdout = compile_result.get('stdout', '')
    build_result.compile_stderr = compile_result.get('stderr', '')
    build_result.compile_log = str(compile_result)
    build_result.is_function_referenced = referenced

  def _validate_fuzz_target_and_build_script(self, cur_round: int,
                                             build_result: BuildResult) -> None:
    """Validates the new fuzz target and build script."""
    # Steps:
    #   1. Recompile without modifying the build script, in case LLM is wrong.
    #   2. Recompile with the modified build script, if any.
    build_script_source = build_result.build_script_source

    logger.info('First compile fuzz target without modifying build script.',
                trial=build_result.trial)
    build_result.build_script_source = ''
    self._validate_fuzz_target_and_build_script_via_compile(
        cur_round, build_result)

    if not build_result.success and build_script_source:
      logger.info('Then compile fuzz target with modified build script.',
                  trial=build_result.trial)
      build_result.build_script_source = build_script_source
      self._validate_fuzz_target_and_build_script_via_compile(
          cur_round, build_result)

  def _validate_fuzz_target_references_function(
      self, compilation_tool: ProjectContainerTool, benchmark: Benchmark,
      cur_round: int, trial: int) -> bool:
    """Validates if the LLM generated fuzz target assembly code references
    function-under-test."""
    disassemble_result = compilation_tool.execute(
        'objdump --disassemble=LLVMFuzzerTestOneInput -d '
        f'/out/{benchmark.target_name}')
    function_referenced = (disassemble_result.returncode == 0 and
                           benchmark.function_name in disassemble_result.stdout)
    logger.debug('ROUND %02d Final fuzz target function referenced: %s',
                 cur_round,
                 function_referenced,
                 trial=trial)
    if not function_referenced:
      logger.debug('ROUND %02d Final fuzz target function not referenced',
                   cur_round,
                   trial=trial)
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
    logger.info('===== ROUND %02d Recompile =====',
                cur_round,
                trial=build_result.trial)
    start_time = time.time()
    compile_process = compilation_tool.compile()
    end_time = time.time()
    logger.debug('ROUND %02d compilation time: %s',
                 cur_round,
                 timedelta(seconds=end_time - start_time),
                 trial=build_result.trial)
    compile_succeed = compile_process.returncode == 0
    logger.debug('ROUND %02d Fuzz target compiles: %s',
                 cur_round,
                 compile_succeed,
                 trial=build_result.trial)

    # Double-check binary.
    ls_result = compilation_tool.execute(f'ls /out/{benchmark.target_name}')
    binary_exists = ls_result.returncode == 0
    logger.debug('ROUND %02d Final fuzz target binary exists: %s',
                 cur_round,
                 binary_exists,
                 trial=build_result.trial)

    # Validate if function-under-test is referenced by the fuzz target.
    function_referenced = self._validate_fuzz_target_references_function(
        compilation_tool, benchmark, cur_round, build_result.trial)

    compilation_tool.terminate()
    self._update_build_result(build_result,
                              compile_process=compile_process,
                              status=compile_succeed and binary_exists,
                              referenced=function_referenced)

  def _container_handle_conclusion(self, cur_round: int, args: dict,
                                   build_result: BuildResult) -> Optional[dict]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=build_result.trial)

    self._update_fuzz_target_and_build_script(cur_round, args, build_result)

    self._validate_fuzz_target_and_build_script(cur_round, build_result)
    if build_result.success:
      logger.info('***** Prototyper succeded in %02d rounds *****',
                  cur_round,
                  trial=build_result.trial)
      return None

    if not build_result.compiles:
      logger.info('***** Failed to recompile in %02d rounds *****',
                  cur_round,
                  trial=build_result.trial)
      content = {
          'compilation_result':
              str(build_result.compiles),
          'stdout':
              build_result.compile_stdout,
          'stderr':
              build_result.compile_stderr,
          'fix_guide': (
              'Failed to build fuzz target. Analyze the stdout, stderr, the fuzz '
              'target, and the build script carefully '
              'to identify the root cause. Avoid making random changes to the fuzz '
              'target or build script without a clear understanding of the error. '
              'If necessary, #include necessary headers and #define required macros'
              'or constants in the fuzz target, or adjust compiler flags to link '
              'required libraries in the build script. After collecting information'
              ', analyzing and understanding the error root cause, YOU MUST take at'
              ' least one step to validate your theory with source code evidence. '
              'Only if your theory is verified, respond the revised fuzz target and'
              'build script in FULL.\n'
              'Always try to learn from the source code about how to fix errors, '
              'for example, search for the key words (e.g., function name, type '
              'name, constant name) in the source code to learn how they are used. '
              'Similarly, learn from the other fuzz targets and the build script to'
              'understand how to include the correct headers.\n'
              'Focus on writing a minimum buildable fuzz target that calls the '
              'target function. We can increase its complexity later, but first try'
              'to make it compile successfully.'
              'If an error happens repeatedly and cannot be fixed, try to '
              'mitigate it. For example, replace or remove the line.')
      }
    elif not build_result.is_function_referenced and not args.get(
        'referenced', False):
      logger.info(
          '***** Fuzz target does not reference function-under-test in %02d '
          'rounds *****',
          cur_round,
          trial=build_result.trial)
      content = {
          'compilation_result':
              str(build_result.compiles),
          'stdout':
              build_result.compile_stdout,
          'stderr':
              build_result.compile_stderr,
          'fix_guide': (
              'The fuzz target builds successfully, but the target function '
              f'`{build_result.benchmark.function_signature}` was not used by '
              '`LLVMFuzzerTestOneInput` in fuzz target. YOU MUST CALL FUNCTION '
              f'`{build_result.benchmark.function_signature}` INSIDE FUNCTION '
              '`LLVMFuzzerTestOneInput`.')
      }
    else:
      content = {
          'compilation_result': str(build_result.compiles),
          'stdout': build_result.compile_stdout,
          'stderr': build_result.compile_stderr,
          'fix_guide': 'Unknown compilation failure'
      }

    return args | content

  def _call_function(self, cur_round: int, call: FunctionCall,
                     build_result: BuildResult) -> Optional[Part]:
    """Calls tool functions based on LLM response."""
    if call.name == 'bash':
      content = self._container_handle_bash_command(call.args,
                                                    self.inspect_tool)
    elif call.name == 'compile':
      content = self._container_handle_conclusion(cur_round, call.args,
                                                  build_result)
      if content is None:
        return None

    else:
      content = self._container_handle_invalid_tool_usage(
          call.args, self.inspect_tool)
    return Part.from_function_response(name=call.name,
                                       response={'content': content})

  def _container_tool_reaction(self, cur_round: int,
                               response: GenerationResponse,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Executes bash command or validates fuzz targets."""
    results = []
    for call in response.candidates[0].function_calls:
      result = self._call_function(cur_round, call, build_result)
      if result is None:
        return None
      results.append(result)
    return DefaultTemplateBuilder(self.llm, initial=results).build([])

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    logger.info('Executing Prototyper', trial=last_result.trial)
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    cur_round = 1
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})
    prompt = self._initial_prompt(result_history)
    try:
      client = self._initialize_chat_session()
      while prompt and cur_round < MAX_ROUND:
        response = self.chat_llm(cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=last_result.trial)
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)
        cur_round += 1
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s',
                   self.inspect_tool.container_id,
                   trial=last_result.trial)
      self.inspect_tool.terminate()
    return build_result
