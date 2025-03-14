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
"""An LLM agent to analyze and provide insight of a fuzz target's runtime crash.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
import subprocess as sp
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from experiment import evaluator as evaluator_lib
from llm_toolkit import prompt_builder
from llm_toolkit.prompts import Prompt
from results import CrashResult, Result, RunResult
from tool.lldb_tool import LLDBTool

MAX_ROUND = 100


class CrashAnalyzer(BaseAgent):
  """The Agent to analyze a runtime crash and provide insight to fuzz target."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]

    if isinstance(last_result, RunResult):
      default_prompt_builder = prompt_builder.DefaultTemplateBuilder(
          model=self.llm, benchmark=last_result.benchmark)
      prompt = default_prompt_builder.build_triager_prompt(
          last_result.benchmark, last_result.fuzz_target_source,
          last_result.run_error, last_result.crash_func)
      return prompt

    logger.error("Expected a RunResult object in results list",
                 trial=self.trial)
    return prompt_builder.DefaultTemplateBuilder(self.llm).build([])

  def _format_lldb_execution_result(
      self,
      process: sp.CompletedProcess,
      previous_prompt: Optional[Prompt] = None) -> str:
    """Formats a prompt based on lldb execution result."""
    if previous_prompt:
      previous_prompt_text = previous_prompt.get()
    else:
      previous_prompt_text = ''
    stdout = self.llm.truncate_prompt(process.stdout,
                                      previous_prompt_text).strip()
    stderr = self.llm.truncate_prompt(process.stderr,
                                      stdout + previous_prompt_text).strip()
    return (f'<lldb>\n{process.args}\n</lldb>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{stdout}\n</stdout>\n'
            f'<stderr>\n{stderr}\n</stderr>\n')

  def _container_handle_lldb_command(self, response: str, tool: LLDBTool,
                                     prompt: Prompt) -> Prompt:
    """Handles the command from LLM with lldb |tool|."""
    prompt_text = ''
    for command in self._parse_tags(response, 'lldb'):
      prompt_text += self._format_lldb_execution_result(
          tool.execute(command), previous_prompt=prompt) + '\n'
      prompt.append(prompt_text)
    return prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   crash_result: CrashResult):
    """Parses LLM conclusion, analysis and suggestion."""
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=self.trial)

    conclusion = self._parse_tag(response, 'conclusion')
    if conclusion == 'Crash is caused by bug in fuzz driver.':
      crash_result.true_bug = False
    elif conclusion == 'Crash is caused by bug in project.':
      crash_result.true_bug = True
    else:
      logger.error('***** Failed to match conclusion in %02d rounds *****',
                   cur_round,
                   trial=self.trial)

    crash_result.insight = self._parse_tag(response, 'analysis and suggestion')
    if not crash_result.insight:
      logger.error('Round %02d No analysis and suggestion in conclusion: %s',
                   cur_round,
                   response,
                   trial=self.trial)

  def _container_tool_reaction(self, cur_round: int, response: str,
                               crash_result: CrashResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    if self._parse_tag(response, 'conclusion'):
      return self._container_handle_conclusion(cur_round, response,
                                               crash_result)
    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])
    return self._container_handle_lldb_command(response, self.analyze_tool,
                                               prompt)

  def execute(self, result_history: list[Result]) -> CrashResult:
    """Executes the agent based on previous run result."""
    WorkDirs(self.args.work_dirs.base) 
    last_result = result_history[-1]
    benchmark = last_result.benchmark
    logger.info('Executing Crash Analyzer', trial=self.trial)
    assert isinstance(last_result, RunResult)

    generated_target_name = os.path.basename(benchmark.target_path)
    sample_id = os.path.splitext(generated_target_name)[0]
    generated_oss_fuzz_project = (
        f'{benchmark.id}-{sample_id}-lldb-{self.trial:02d}')
    generated_oss_fuzz_project = evaluator_lib.rectify_docker_tag(
        generated_oss_fuzz_project)

    fuzz_target_path = os.path.join(last_result.work_dirs.fuzz_targets,
                                    f'{self.trial:02d}.fuzz_target')
    build_script_path = os.path.join(last_result.work_dirs.fuzz_targets,
                                     f'{self.trial:02d}.build_script')

    evaluator_lib.Evaluator.create_ossfuzz_project_with_lldb(
        benchmark, generated_oss_fuzz_project, fuzz_target_path, last_result,
        build_script_path)

    self.analyze_tool = LLDBTool(
        benchmark,
        # project=generated_oss_fuzz_project,
        result=last_result,
        name='lldb',
        project_name=generated_oss_fuzz_project)
    self.analyze_tool.execute('compile > /dev/null')
    self.analyze_tool.execute('lldb')
    prompt = self._initial_prompt(result_history)
    prompt.add_problem(self.analyze_tool.tutorial())
    crash_result = CrashResult.from_existing_result(last_result)
    cur_round = 1
    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < MAX_ROUND:
        response = self.chat_llm(cur_round=cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=self.trial)
        prompt = self._container_tool_reaction(cur_round, response,
                                               crash_result)
        cur_round += 1
        self._sleep_random_duration(trial=self.trial)
    finally:
      # Cleanup: stop the container
      logger.debug('Stopping the crash analyze container %s',
                   self.analyze_tool.container_id,
                   trial=self.trial)
      self.analyze_tool.terminate()

    return crash_result
