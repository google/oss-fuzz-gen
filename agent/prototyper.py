"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import subprocess as sp
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from llm_toolkit.prompt_builder import DefaultTemplateBuilder
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.container_tool import ProjectContainerTool

MAX_ROUND = 100


class Prototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    benchmark = results[-1].benchmark

    default_prompt_builder = DefaultTemplateBuilder(model=self.llm,
                                                    benchmark=benchmark)
    prompt = default_prompt_builder.build([])
    # TODO(dongge): Find a way to save prompt and log for agents
    return prompt

  def _update_fuzz_target_and_build_script(self, cur_round: int, response: str,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    fuzz_target_source = self._filter_code(
        self._parse_tag(response, 'fuzz target'))
    build_result.fuzz_target_source = fuzz_target_source  #assign new fuzz target
    if fuzz_target_source:
      logger.debug('ROUND %02d Parsed fuzz target from LLM: %s', cur_round,
                   fuzz_target_source)
    else:
      logger.error('ROUND %02d No fuzz target source code in conclusion: %s',
                   cur_round, response)

    build_script_source = self._filter_code(
        self._parse_tag(response, 'build script'))
    build_result.build_script_source = build_script_source  #assign new build script
    if build_script_source:
      logger.debug('ROUND %02d Parsed build script from LLM: %s', cur_round,
                   build_script_source)
    else:
      logger.debug('ROUND %02d No build script in conclusion: %s', cur_round,
                   response)

  def _update_build_result(self, buid_result: BuildResult,
                           compile_process: sp.CompletedProcess,
                           status: bool) -> None:
    """Updates the build result with the latest info."""
    buid_result.compiles = status
    buid_result.compile_error = compile_process.stderr
    buid_result.compile_log = self._format_bash_execution_result(
        compile_process)

  def _validate_fuzz_target_and_build_script(self, cur_round: int,
                                             build_result: BuildResult) -> None:
    """Validates the new fuzz target and build script."""
    benchmark = build_result.benchmark
    compilation_tool = ProjectContainerTool(
        benchmark=benchmark
    )  #second time, use existing image, create new container

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
    compile_command = 'compile > /dev/null'
    compile_process = compilation_tool.execute(compile_command)
    compile_succeed = compile_process.returncode == 0
    logger.debug('ROUND %02d Fuzz target compile Succeessfully: %s', cur_round,
                 compile_succeed)

    # Double-check binary.
    ls_result = compilation_tool.execute(f'ls /out/{benchmark.target_name}')
    binary_exists = ls_result.returncode == 0
    logger.debug('ROUND %02d Final fuzz target binary exists: %s', cur_round,
                 binary_exists)
    compilation_tool.terminate()

    self._update_build_result(build_result,
                              compile_process=compile_process,
                              status=compile_succeed and binary_exists)

  def _container_handle_conclusion(
      self, cur_round: int, response: str,
      build_result: BuildResult) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    logger.info('----- ROUND %02d Received conclusion -----', cur_round)

    self._update_fuzz_target_and_build_script(cur_round, response, build_result)

    self._validate_fuzz_target_and_build_script(cur_round, build_result)
    if build_result.compiles:
      logger.info('***** Prototyper succeded in %02d rounds *****', cur_round)
      return None  # if success, return None

    logger.info('***** Failed to recompile in %02d rounds *****', cur_round)
    prompt_text = ('Failed to build fuzz target. Here is the fuzz target, build'
                   ' script, compliation command, and other compilation runtime'
                   ' output.\n<fuzz target>\n'
                   f'{build_result.fuzz_target_source}\n</fuzz target>\n'
                   f'<build script>\n{build_result.build_script_source}\n'
                   '</build script>\n'
                   f'{build_result.compile_log}')
    prompt = DefaultTemplateBuilder(self.llm, initial=prompt_text).build([])
    return prompt

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    if self._parse_tag(response, 'conclusion'):
      return self._container_handle_conclusion(
          cur_round, response,
          build_result)  # if build success, return none <=> exit chat
    return self._container_handle_bash_command(
        cur_round, response,
        self.inspect_tool)  # return non-none prompt <=> continue chat

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    logger.info('Executing Prototyper')
    last_result = result_history[-1]
    prompt = self._initial_prompt(
        result_history)  #prompt to first generate driver
    #TODO: delete
    logger.info('prototyper initial prompt: %s', prompt.get())
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(
        benchmark, name='inspect')  #first time, prepare image, start container
    self.inspect_tool.execute(
        '{compile && rm -rf /out/*} > /dev/null')  #why compile here?
    cur_round = 1
    prompt.add_problem(self.inspect_tool.tutorial())
    #TODO: delete
    logger.info('prototyper after append tutorial prompt: %s', prompt.get())
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: ''})
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < MAX_ROUND:  #when prompt is empty or cur_round >= MAX_ROUND, exit. empty prompt <=> have conclusion, build success.
        logger.info('ROUND %02d agent prompt: %s', cur_round, prompt.get())
        response = self.llm.chat_llm(client=client, prompt=prompt)
        logger.debug('ROUND %02d LLM response: %s', cur_round, response)
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)
        cur_round += 1
        self._sleep_random_duration()
    finally:
      # Cleanup: stop and remove the container
      logger.debug(
          'Stopping and removing the inspect container %s',  # not been removed yet
          self.inspect_tool.container_id)
      self.inspect_tool.terminate()  # only stop the container

    return build_result  #fuzz target and build script are saved here
