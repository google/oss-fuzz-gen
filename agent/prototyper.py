"""An LLM agent to generate a simple fuzz target prototype that can build.
Use it as a usual module locally, or as script in cloud builds.
"""
import argparse
import logging
import os
import re
import subprocess as sp
import threading
from typing import Optional

from agent.base_agent import BaseAgent
from llm_toolkit.models import LLM
from llm_toolkit.prompt_builder import DefaultTemplateBuilder
from llm_toolkit.prompts import Prompt
from results import BuildResult, Result
from tool.base_tool import BaseTool
from tool.container_tool import ProjectContainerTool

# TODO(dongge): Replace this with google-cloud-log in a module.
# Custom logging filter to add thread-local information to log records
thread_local = threading.local()

#TODO(dongge): Replace process ID with trial ID.
logging.basicConfig(level=logging.DEBUG,
                    format=('%(asctime)s [Trial: %02d] %(levelname)s '
                            '[%(module)s.%(funcName)s]: %(message)s'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def write_to_file(file_path: str, file_content: str):
  with open(file_path, 'w') as file:
    file.writelines(file_content)


MAX_ROUND = 100


class Prototyper(BaseAgent):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def __init__(self,
               trail: int,
               llm: LLM,
               tools: Optional[list[BaseTool]] = None,
               args: Optional[argparse.Namespace] = None,
               name: str = ''):
    super().__init__(llm, tools, args, name)
    self.trial: int = trail

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    benchmark = results[-1].benchmark

    default_prompt_builder = DefaultTemplateBuilder(model=self.llm,
                                                    benchmark=benchmark)
    prompt = default_prompt_builder.build([])
    work_dirs = results[-1].work_dirs
    prompt.save(work_dirs.prompt)
    return prompt

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the XML-style tags from LLM response."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return match.group(1).strip() if match else ''

  def _format_tool_execution_result(self, process: sp.CompletedProcess) -> str:
    return (f'<bash>\n{process.args}\n</bash>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{process.stdout}\n</stdout>\n'
            f'<stderr>\n{process.stderr}\n</stderr>\n')

  def _container_handle_command(self, cur_round: int, response: str) -> Prompt:
    """Handles the command from LLM with container tool."""
    command = self._parse_tag(response, 'bash')
    if command:
      prompt_text = self._format_tool_execution_result(
          self.inspect_tool.execute(command))
    else:
      logger.warning('ROUND %d No BASH command from LLM response: %s',
                     cur_round,
                     response,
                     extra={'trial': self.trial})
      prompt_text = ('No bash command received, Please follow the '
                     'interaction protocols:\n'
                     f'{self.inspect_tool.tutorial()}')
    return DefaultTemplateBuilder(self.llm, None, initial=prompt_text).build([])

  def _filter_code(self, raw_code_block: str) -> str:
    """Filter out irrelevant lines from |raw_code_block|."""
    # TODO(dongge): Move this function to a separate module.
    # Remove markdown-style code block symbols.
    filtered_lines = [
        line for line in raw_code_block.splitlines()
        if not line.strip().startswith('```')
    ]
    filtered_code_block = '\n'.join(filtered_lines)
    return filtered_code_block

  def _update_fuzz_target_and_build_script(self, cur_round: int, response: str,
                                           build_result: BuildResult) -> None:
    """Updates fuzz target and build script in build_result with LLM response.
    """
    fuzz_target_source = self._filter_code(
        self._parse_tag(response, 'fuzz target'))
    build_result.fuzz_target_source = fuzz_target_source
    if fuzz_target_source:
      logger.debug('ROUND %d Parsed fuzz target from LLM: %s',
                   cur_round,
                   fuzz_target_source,
                   extra={'trial': self.trial})
    else:
      logger.error('ROUND %d No fuzz target source code in conclusion: %s',
                   cur_round,
                   response,
                   extra={'trial': self.trial})

    build_script_source = self._filter_code(
        self._parse_tag(response, 'build script'))
    build_result.build_script_source = build_script_source
    if build_script_source:
      logger.debug('ROUND %d Parsed build script from LLM: %s',
                   cur_round,
                   build_script_source,
                   extra={'trial': self.trial})
    else:
      logger.debug('ROUND %d No build script in conclusion: %s',
                   cur_round,
                   response,
                   extra={'trial': self.trial})

  def _update_build_result(self, buid_result: BuildResult,
                           compile_process: sp.CompletedProcess,
                           status: bool) -> None:
    """Updates the build result with the latest info."""
    buid_result.status = status
    buid_result.error = compile_process.stderr
    buid_result.full_log = self._format_tool_execution_result(compile_process)

  def _validate_fuzz_target_and_build_script(self, cur_round: int,
                                             build_result: BuildResult) -> None:
    """Validates the new fuzz target and build script."""
    benchmark = build_result.benchmark
    compilation_tool = ProjectContainerTool(bechmark=benchmark)

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
    logger.info('===== ROUND %d Recompile =====',
                cur_round,
                extra={'trial': self.trial})
    compile_command = 'compile > /dev/null'
    compile_process = compilation_tool.execute(compile_command)
    compile_succeed = compile_process.returncode == 0
    logger.debug('ROUND %d Fuzz target compile Succeessfully: %s',
                 cur_round,
                 compile_succeed,
                 extra={'trial': self.trial})

    # Double-check binary.
    ls_result = compilation_tool.execute(f'ls /out/{benchmark.target_name}')
    binary_exists = ls_result.returncode == 0
    logger.debug('ROUND %d Final fuzz target binary exists: %s',
                 cur_round,
                 binary_exists,
                 extra={'trial': self.trial})
    compilation_tool.terminate()

    self._update_build_result(build_result,
                              compile_process=compile_process,
                              status=compile_succeed and binary_exists)

  def _container_handle_conclusion(
      self, cur_round: int, response: str,
      build_result: BuildResult) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    logger.info('----- ROUND %d Received conclusion -----',
                cur_round,
                extra={'trial': self.trial})

    self._update_fuzz_target_and_build_script(cur_round, response, build_result)

    self._validate_fuzz_target_and_build_script(cur_round, build_result)
    if build_result.status:
      logger.info('***** Prototyper succeded in %d rounds *****',
                  cur_round,
                  extra={'trial': self.trial})
      write_to_file(
          os.path.join(build_result.work_dirs.fixed_targets,
                       f'{build_result.trial}.fuzz_target'),
          build_result.fuzz_target_source)
      write_to_file(
          os.path.join(build_result.work_dirs.fixed_targets,
                       f'{build_result.trial}.build_script'),
          build_result.build_script_source)
      return None

    logger.info('***** Failed to recompile in %d rounds *****',
                cur_round,
                extra={'trial': self.trial})
    prompt_text = ('Failed to build fuzz target. Here is the fuzz target, build'
                   ' script, compliation command, and other compilation runtime'
                   ' output.\n<fuzz target>\n'
                   f'{build_result.fuzz_target_source}\n</fuzz target>\n'
                   f'<build script>\n{build_result.build_script_source}\n'
                   '</build script>\n'
                   f'{build_result.full_log}')
    prompt = DefaultTemplateBuilder(self.llm, initial=prompt_text).build([])
    return prompt

  def _container_tool_reaction(self, cur_round: int, response: str,
                               build_result: BuildResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    if self._parse_tag(response, 'conclusion'):
      return self._container_handle_conclusion(cur_round, response,
                                               build_result)
    return self._container_handle_command(cur_round, response)

  def execute(self, prev_results: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    logger.info('Executing Prototyper', extra={'trial': self.trial})
    last_result = prev_results[-1]
    prompt = self._initial_prompt(prev_results)
    benchmark = last_result.benchmark
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.execute('{compile && rm -rf /out/*} > /dev/null')
    cur_round = 1
    prompt.append(self.inspect_tool.tutorial())
    build_result = BuildResult(benchmark=benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               agent_dialogs={self.name: ''})
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < MAX_ROUND:
        logger.debug('ROUND %d agent prompt: %s',
                     cur_round,
                     prompt.get(),
                     extra={'trial': self.trial})
        response = self.llm.chat_llm(client=client, prompt=prompt)
        logger.debug('ROUND %d LLM response: %s',
                     cur_round,
                     response,
                     extra={'trial': self.trial})
        prompt = self._container_tool_reaction(cur_round, response,
                                               build_result)
        cur_round += 1
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s...',
                   self.inspect_tool.container_id,
                   extra={'trial': self.trial})
      self.inspect_tool.terminate()
    return build_result
