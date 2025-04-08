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
"""An LLM agent to analyze and provide insight of a fuzz target's low coverage.
Use it as a usual module locally, or as script in cloud builds.
"""
import os
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from experiment.workdir import WorkDirs
from llm_toolkit import prompt_builder
from llm_toolkit.prompt_builder import CoverageAnalyzerTemplateBuilder
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, CoverageResult, Result, RunResult
from tool.container_tool import ProjectContainerTool

INVALID_PRMOT_PATH = os.path.join('prompts', 'agent',
                                  'coverage-analyzer-invalid-response.txt')


class CoverageAnalyzer(BaseAgent):
  """The Agent to refine a compilable fuzz target for higher coverage."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]
    benchmark = last_result.benchmark

    if not isinstance(last_result, RunResult):
      logger.error('The last result in %s is not RunResult: %s',
                   self.name,
                   results,
                   trial=self.trial)
      return Prompt()

    builder = CoverageAnalyzerTemplateBuilder(self.llm, benchmark, last_result)
    prompt = builder.build(example_pair=[],
                           tool_guides=self.inspect_tool.tutorial(),
                           project_dir=self.inspect_tool.project_dir)
    # TODO: A different file name/dir.
    prompt.save(self.args.work_dirs.prompt)

    return prompt

  def _container_handle_conclusion(self, cur_round: int, response: str,
                                   coverage_result: CoverageResult,
                                   prompt: Prompt) -> Optional[Prompt]:
    """Runs a compilation tool to validate the new fuzz target and build script
    from LLM."""
    conclusion = self._parse_tag(response, 'conclusion')
    if not conclusion:
      return prompt
    logger.info('----- ROUND %02d Received conclusion -----',
                cur_round,
                trial=self.trial)

    coverage_result.improve_required = conclusion.strip().lower() == 'true'
    coverage_result.insight = self._parse_tag(response, 'insights')
    coverage_result.suggestions = self._parse_tag(response, 'suggestions')

    return None

  def _container_tool_reaction(
      self, cur_round: int, response: str, run_result: RunResult,
      coverage_result: CoverageResult) -> Optional[Prompt]:
    """Validates LLM conclusion or executes its command."""
    del run_result
    prompt = prompt_builder.DefaultTemplateBuilder(self.llm, None).build([])

    prompt = self._container_handle_bash_commands(response, self.inspect_tool,
                                                  prompt)
    # Only report conclusion when no more bash investigation is required.
    if not prompt.gettext():
      # Then build fuzz target.
      prompt = self._container_handle_conclusion(cur_round, response,
                                                 coverage_result, prompt)
      if prompt is None:
        # Succeeded.
        return None

    # Finally check invalid responses.
    if not response or not prompt.get():
      prompt = self._container_handle_invalid_tool_usage(
          self.inspect_tool, cur_round, response, prompt)
      with open(INVALID_PRMOT_PATH, 'r') as prompt_file:
        prompt.append(prompt_file.read())

    return prompt

  def execute(self, result_history: list[Result]) -> AnalysisResult:
    """Executes the agent to analyze the root cause to the low coverage."""
    WorkDirs(self.args.work_dirs.base, keep=True)
    last_result = result_history[-1]
    assert isinstance(last_result, RunResult)

    logger.info('Executing %s', self.name, trial=last_result.trial)
    benchmark = last_result.benchmark
    # TODO(dongge): Use the generated fuzz target and build script here.
    self.inspect_tool = ProjectContainerTool(benchmark, name='inspect')
    self.inspect_tool.compile(extra_commands=' && rm -rf /out/* > /dev/null')
    cur_round = 1
    coverage_result = CoverageResult()
    prompt = self._initial_prompt(result_history)

    try:
      client = self.llm.get_chat_client(model=self.llm.get_model())
      while prompt and cur_round < self.max_round:
        response = self.chat_llm(cur_round,
                                 client=client,
                                 prompt=prompt,
                                 trial=last_result.trial)
        prompt = self._container_tool_reaction(cur_round, response, last_result,
                                               coverage_result)
        cur_round += 1
    finally:
      # Cleanup: stop and remove the container
      logger.debug('Stopping and removing the inspect container %s',
                   self.inspect_tool.container_id,
                   trial=last_result.trial)
      self.inspect_tool.terminate()

    analysis_result = AnalysisResult(
        author=self,
        run_result=last_result,
        coverage_result=coverage_result,
        chat_history={self.name: coverage_result.to_dict()})
    return analysis_result
