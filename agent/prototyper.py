"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import subprocess as sp
import time
from datetime import timedelta
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from data_prep.project_context.context_introspector import ContextRetriever
from experiment.benchmark import Benchmark
from llm_toolkit.prompt_builder import EXAMPLES as EXAMPLE_FUZZ_TARGETS
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
                                  project_context_content=context_info,
                                  tool_guides=self.inspect_tool.tutorial())
    # prompt = prompt_builder.build(example_pair=EXAMPLE_FUZZ_TARGETS.get(
    #     benchmark.language, []),
    #                               tool_guides=self.inspect_tool.tutorial())
    return prompt

  def _update_fuzz_target_and_build_script(self, cur_round: int, response: str,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    fuzz_target_source = self._filter_code(
        self._parse_tag(response, 'fuzz target'))
    build_result.fuzz_target_source = fuzz_target_source
    if fuzz_target_source:
      logger.debug('ROUND %02d Parsed fuzz target from LLM: %s', cur_round,
                   fuzz_target_source)
    else:
      logger.error('ROUND %02d No fuzz target source code in conclusion: %s',
                   cur_round, response)

    build_script_source = self._filter_code(
        self._parse_tag(response, 'build script'))
    # Sometimes LLM adds chronos, which makes no sense for new build scripts.
    build_result.build_script_source = build_script_source.replace(
        'source /src/chronos.sh', '')
    if build_script_source:
      logger.debug('ROUND %02d Parsed build script from LLM: %s', cur_round,
                   build_script_source)
    else:
      logger.debug('ROUND %02d No build script in conclusion: %s', cur_round,
                   response)

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, status: bool,
                           referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = status
    build_result.compile_error = compile_process.stderr
    build_result.compile_log = self._format_bash_execution_result(
        compile_process)
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

  def _container_handle_conclusion(
      self, cur_round: int, response: str,
      build_result: BuildResult) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    logger.info('----- ROUND %02d Received conclusion -----', cur_round)

    self._update_fuzz_target_and_build_script(cur_round, response, build_result)

    self._validate_fuzz_target_and_build_script(cur_round, build_result)
    if build_result.success:
      logger.info('***** Prototyper succeded in %02d rounds *****', cur_round)
      return None

    if not build_result.compiles:
      compile_log = self.llm.truncate_prompt(build_result.compile_log)
      logger.info('***** Failed to recompile in %02d rounds *****', cur_round)
      prompt_text = (
          'Failed to build fuzz target. Here is the fuzz target, build script, '
          'compliation command, and other compilation runtime output. Analyze '
          'the error messages, the fuzz target, and the build script carefully '
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
          'mitigate it. For example, replace or remove the line.'
          f'<fuzz target>\n{build_result.fuzz_target_source}\n</fuzz target>\n'
          f'<build script>\n{build_result.build_script_source}\n</build script>'
          f'\n<compilation log>\n{compile_log}\n</compilation log>\n')
    elif not build_result.is_function_referenced:
      logger.info(
          '***** Fuzz target does not reference function-under-test in %02d '
          'rounds *****', cur_round)
      prompt_text = (
          'The fuzz target builds successfully, but the target function '
          f'`{build_result.benchmark.function_signature}` was not used by '
          '`LLVMFuzzerTestOneInput` in fuzz target. YOU MUST CALL FUNCTION '
          f'`{build_result.benchmark.function_signature}` INSIDE FUNCTION '
          '`LLVMFuzzerTestOneInput`.')
    else:
      prompt_text = ''

    prompt = DefaultTemplateBuilder(self.llm, initial=prompt_text).build([])
    return prompt

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    if self._parse_tag(response, 'conclusion'):
      return self._container_handle_conclusion(cur_round, response,
                                               build_result)
    return self._container_handle_bash_command(cur_round, response,
                                               self.inspect_tool)

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    logger.info('Executing Prototyper')
    last_result = result_history[-1]
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
      client = self.llm.get_chat_client(model=self.llm.get_model())
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
