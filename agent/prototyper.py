"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import copy
import os
import subprocess as sp
import time
from datetime import timedelta
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from data_prep import project_targets
from data_prep.project_context.context_introspector import ContextRetriever
from experiment.benchmark import Benchmark
from llm_toolkit import prompt_builder
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.container_tool import ProjectContainerTool

MAX_ROUND = 100


class Prototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    benchmark = results[-1].benchmark

    if benchmark.use_project_examples:
      project_examples = project_targets.generate_data(
          benchmark.project,
          benchmark.language,
          cloud_experiment_bucket=self.args.cloud_experiment_bucket)
    else:
      project_examples = []

    if self.args.context:
      retriever = ContextRetriever(benchmark)
      context_info = retriever.get_context_info()
    else:
      context_info = {}

    builder = prompt_builder.PrototyperTemplateBuilder(
        model=self.llm,
        benchmark=benchmark,
    )
    prompt = builder.build(example_pair=prompt_builder.EXAMPLES.get(
        benchmark.language, []),
                           project_example_content=project_examples,
                           project_context_content=context_info,
                           tool_guides=self.inspect_tool.tutorial(),
                           project_dir=self.inspect_tool.project_dir)
    return prompt

  def _update_fuzz_target_and_build_script(self, cur_round: int, response: str,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    fuzz_target_source = self._filter_code(
        self._parse_tag(response, 'fuzz target'))
    build_result.fuzz_target_source = fuzz_target_source
    if fuzz_target_source:
      logger.debug('ROUND %02d Parsed fuzz target from LLM: %s',
                   cur_round,
                   fuzz_target_source,
                   trial=build_result.trial)
    else:
      logger.error('ROUND %02d No fuzz target source code in conclusion: %s',
                   cur_round,
                   response,
                   trial=build_result.trial)

    build_script_source = self._filter_code(
        self._parse_tag(response, 'build script'))
    # Sometimes LLM adds chronos, which makes no sense for new build scripts.
    build_result.build_script_source = build_script_source.replace(
        'source /src/chronos.sh', '')
    if build_script_source:
      logger.debug('ROUND %02d Parsed build script from LLM: %s',
                   cur_round,
                   build_script_source,
                   trial=build_result.trial)
    else:
      logger.debug('ROUND %02d No build script in conclusion: %s',
                   cur_round,
                   response,
                   trial=build_result.trial)

  def _update_build_result(self, build_result: BuildResult,
                           compile_process: sp.CompletedProcess, compiles: bool,
                           binary_exists: bool, referenced: bool) -> None:
    """Updates the build result with the latest info."""
    build_result.compiles = compiles
    build_result.compile_error = compile_process.stderr
    build_result.compile_log = self._format_bash_execution_result(
        compile_process)
    build_result.binary_exists = binary_exists
    build_result.is_function_referenced = referenced

  def _validate_fuzz_target_and_build_script(
      self, cur_round: int, build_result: BuildResult
  ) -> tuple[Optional[BuildResult], Optional[BuildResult]]:
    """Validates the new fuzz target and build script."""
    # Steps:
    #   1. Recompile without modifying the build script, in case LLM is wrong.
    #   2. Recompile with the modified build script, if any.
    build_result_alt = None
    if build_result.build_script_source:
      build_result_alt = copy.deepcopy(build_result)
      logger.info('First compile fuzz target without modifying build script.',
                  trial=build_result_alt.trial)
      build_result_alt.build_script_source = ''
      self._validate_fuzz_target_and_build_script_via_compile(
          cur_round, build_result_alt)

    # No need to run expensive build_result, when *_alt is perfect.
    if build_result_alt and build_result_alt.success:
      return build_result_alt, None

    # New fuzz target + has new build.sh.
    logger.info('Compile fuzz target with modified build script.',
                trial=build_result.trial)
    self._validate_fuzz_target_and_build_script_via_compile(
        cur_round, build_result)

    # Although build_result_alt is not perfect, LLM may still learn from it.
    return build_result_alt, build_result

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
        'cat << "OFG_EOF" > {file_path}\n{file_content}\nOFG_EOF')
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
                              compiles=compile_succeed,
                              binary_exists=binary_exists,
                              referenced=function_referenced)

  def _generate_prompt_from_build_result(
      self, build_result_alt: Optional[BuildResult],
      build_result_ori: Optional[BuildResult], build_result: BuildResult,
      prompt: Prompt, cur_round: int) -> tuple[BuildResult, Optional[Prompt]]:
    """Selects which build result to use and generates a prompt accordingly."""

    # Case 1: Successful.
    if build_result_alt and build_result_alt.success:
      # Preference 1: New fuzz target + default build.sh can compile, save
      # binary to expected path, and reference function-under-test.
      logger.info(
          'Default /src/build.sh works perfectly, no need for a new '
          'buid script',
          trial=build_result.trial)
      logger.info('***** Prototyper succeded in %02d rounds *****',
                  cur_round,
                  trial=build_result.trial)
      return build_result_alt, None

    if build_result_ori and build_result_ori.success:
      # Preference 2: New fuzz target + new build.sh can compile, save
      # binary to expected path, and reference function-under-test.
      logger.info('***** Prototyper succeded in %02d rounds *****',
                  cur_round,
                  trial=build_result.trial)
      return build_result_ori, None

    # Case 2: Binary exits, meaning not referencing function-under-test.
    function_signature = build_result.benchmark.function_signature
    fuzz_target_source = build_result.fuzz_target_source
    build_script_source = build_result.build_script_source
    compile_log = self.llm.truncate_prompt(build_result.compile_log,
                                           extra_text=prompt.get()).strip()
    prompt_text = (
        "The fuzz target's `LLVMFuzzerTestOneInput` did not invoke the "
        f'function-under-test `{function_signature}`:\n'
        f'<fuzz target>\n{fuzz_target_source}\n</fuzz target>\n'
        '{BUILD_TEXT}\n'
        f'<compilation log>\n{compile_log}\n</compilation log>\n'
        'That is NOT enough. YOU MUST MODIFY THE FUZZ TARGET to CALL '
        f'FUNCTION `{function_signature}` **EXPLICITLY OR IMPLICITLY** in '
        '`LLVMFuzzerTestOneInput` to generate a valid fuzz target.\nStudy the '
        'source code for function usages to know how.\n')
    if build_result_alt and build_result_alt.binary_exists:
      # Preference 3: New fuzz target + default build.sh can compile and save
      # binary to expected path, but does not reference function-under-test.
      prompt_text = prompt_text.replace(
          '{BUILD_TEXT}',
          'Althoug `/src/build.bk.sh` compiles and saves the binary to the '
          'correct path:')
      # NOTE: Unsafe to say the following, because /src/build.sh may miss a
      # library required by the function-under-test, and the fuzz target did not
      # invoke the function-under-test either.
      # prompt_text += (
      #     'In addition, given the default /src/build.sh works perfectly, you '
      #     'do not have to generate a new build script and can leave '
      #     '<build script></build script> empty.')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target. YOU MUST NOT OMIT ANY CODE even if it is the same as before.'
          '\n')
      prompt.append(prompt_text)
      return build_result_alt, prompt
    if (build_result_ori and build_result_ori.binary_exists and
        not build_result_ori.build_script_source):
      # Preference 4.1: New fuzz target + default build.sh can compile and save
      # binary to expected path, but does not reference function-under-test.
      prompt_text = prompt_text.replace(
          '{BUILD_TEXT}',
          'Althoug `/src/build.bk.sh` compiles and saves the binary to the '
          'correct path:')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target. YOU MUST NOT OMIT ANY CODE even if it is the same as before.'
          '\n')
      prompt.append(prompt_text)
      return build_result_ori, prompt
    if build_result_ori and build_result_ori.binary_exists:
      # Preference 4.2: New fuzz target + New build.sh can compile and save
      # binary to expected path, but does not reference function-under-test.
      prompt_text = prompt_text.replace(
          '{BUILD_TEXT}',
          'Althoug your build script compiles and saves the binary to the '
          'correct path:\n'
          f'<build script>\n{build_script_source}\n</build script>\n')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target (and the FULL build script, if any). YOU MUST NOT OMIT ANY '
          'CODE even if it is the same as before.\n')
      prompt.append(prompt_text)
      return build_result_ori, prompt

    # Case 3: Compiles, meaning the binary is not saved.
    binary_path = os.path.join('/out', build_result.benchmark.target_name)
    if (build_result_ori and build_result_ori.compiles and
        build_result_ori.build_script_source):
      # Preference 5.1: New fuzz target + new build.sh can compile, but does
      # not save binary to expected path.
      prompt_text = (
          'The fuzz target and build script compiles successfully, but the '
          'final fuzz target binary was not saved to the expected path at '
          f'`{binary_path}`.\n'
          f'<fuzz target>\n{fuzz_target_source}\n</fuzz target>\n'
          f'<build script>\n{build_script_source}\n</build script>\n'
          f'<compilation log>\n{compile_log}\n</compilation log>\n'
          'YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to '
          f'{binary_path}.\n')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target (and the FULL build script, if any). YOU MUST NOT OMIT ANY '
          'CODE even if it is the same as before.\n')
      prompt.append(prompt_text)
      return build_result_ori, prompt
    if (build_result_ori and build_result_ori.compiles and
        not build_result_ori.build_script_source):
      # Preference 5.2: New fuzz target + default build.sh can compile, but does
      # not save binary to expected path, indicating benchmark data error.
      logger.error(
          'The human-written build.sh does not save the fuzz target binary to '
          'expected path /out/%s, indicating incorrect info in benchmark YAML.',
          build_result.benchmark.target_name,
          trial=build_result.trial)
      prompt_text = (
          'The fuzz target compiles successfully with /src/build.bk.sh, but the'
          ' final fuzz target binary was not saved to the expected path at '
          f'`{binary_path}`.\n'
          f'<fuzz target>\n{fuzz_target_source}\n</fuzz target>\n'
          f'<compilation log>\n{compile_log}\n</compilation log>\n'
          'YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to '
          f'{binary_path}.\n')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target (and the FULL build script, if any). YOU MUST NOT OMIT ANY '
          'CODE even if it is the same as before.\n')
      prompt.append(prompt_text)
      return build_result_ori, prompt
    if build_result_alt and build_result_alt.compiles:
      # Preference 6: New fuzz target + default build.sh can compile, but does
      # not save binary to expected path, indicating benchmark data error.
      logger.error(
          'The human-written build.sh does not save the fuzz target binary to '
          'expected path /out/%s, indicating incorrect info in benchmark YAML.',
          build_result.benchmark.target_name,
          trial=build_result.trial)
      prompt_text = (
          'The fuzz target compiles successfully with /src/build.bk.sh, but the'
          ' final fuzz target binary was not saved to the expected path at '
          f'`{binary_path}`.\n'
          f'<fuzz target>\n{fuzz_target_source}\n</fuzz target>\n'
          f'<compilation log>\n{compile_log}\n</compilation log>\n'
          'YOU MUST MODIFY THE BUILD SCRIPT to ensure the binary is saved to '
          f'{binary_path}.\n')
      prompt_text += (
          'When you have a solution later, make sure you output the FULL fuzz '
          'target (and the FULL build script, if any). YOU MUST NOT OMIT ANY '
          'CODE even if it is the same as before.\n')
      prompt.append(prompt_text)
      return build_result_alt, prompt

    # Preference 7: New fuzz target + both `build.sh`s cannot compile. No need
    # to mention the default build.sh.
    # return build_result
    builder = prompt_builder.PrototyperFixerTemplateBuilder(
        model=self.llm,
        benchmark=build_result.benchmark,
        build_result=build_result,
        compile_log=compile_log,
        initial=prompt.get())
    prompt = builder.build(example_pair=[],
                           project_dir=self.inspect_tool.project_dir)
    return build_result, prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   build_result: BuildResult,
                                   prompt: Prompt) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    if not self._parse_tag(response, 'fuzz target'):
      return prompt
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=build_result.trial)

    self._update_fuzz_target_and_build_script(cur_round, response, build_result)

    build_result_alt, build_result_ori = (
        self._validate_fuzz_target_and_build_script(cur_round, build_result))

    # Updates build_result with _alt or _ori, depending on their status.
    build_result, prompt_final = self._generate_prompt_from_build_result(
        build_result_alt, build_result_ori, build_result, prompt, cur_round)

    return prompt_final

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
    prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                  prompt)

    # Then build fuzz target.
    prompt = self._container_handle_conclusion(cur_round, response,
                                               build_result, prompt)
    if prompt is None:
      # Succeeded.
      return None

    # Finally check invalid responses.
    if not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, cur_round, response, prompt)

    return prompt

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
      client = self.llm.get_chat_client(model=self.llm.get_model())
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
