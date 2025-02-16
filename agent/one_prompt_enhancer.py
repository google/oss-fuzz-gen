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
"""An LLM agent to improve a fuzz target's runtime performance.
Use it as a usual module locally, or as script in cloud builds.
"""
import logger
from agent.one_prompt_prototyper import OnePromptPrototyper
from experiment.workdir import WorkDirs
from llm_toolkit.prompt_builder import (DefaultTemplateBuilder,
                                        JvmErrorFixingBuilder)
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, BuildResult, Result

MAX_ROUND = 5


class OnePromptEnhancer(OnePromptPrototyper):
  """The Agent to generate a simple but valid fuzz target from scratch."""

  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """Constructs initial prompt of the agent."""
    last_result = results[-1]
    benchmark = last_result.benchmark

    if not isinstance(last_result, AnalysisResult):
      logger.error('The last result in Enhancer is not AnalysisResult: %s',
                   results,
                   trial=self.trial)
      return Prompt()

    if benchmark.language == 'jvm':
      # TODO: Do this in a separate agent for JVM coverage.
      jvm_coverage_fix = True
      error_desc, errors = '', []
      builder = JvmErrorFixingBuilder(self.llm, benchmark,
                                      last_result.run_result.fuzz_target_source,
                                      errors, jvm_coverage_fix)
      prompt = builder.build([], None, None)
    else:
      error_desc, errors = last_result.semantic_result.get_error_info()
      builder = DefaultTemplateBuilder(self.llm)
      prompt = builder.build_fixer_prompt(benchmark,
                                          last_result.fuzz_target_source,
                                          error_desc,
                                          errors,
                                          context='',
                                          instruction='')
      # TODO: A different file name/dir.
      prompt.save(self.args.work_dirs.prompt)

    return prompt

  def execute(self, result_history: list[Result]) -> BuildResult:
    """Executes the agent based on previous result."""
    last_result = result_history[-1]
    logger.info('Executing One Prompt Enhancer', trial=last_result.trial)
    WorkDirs(self.args.work_dirs.base)

    prompt = self._initial_prompt(result_history)
    cur_round = 1
    build_result = BuildResult(benchmark=last_result.benchmark,
                               trial=last_result.trial,
                               work_dirs=last_result.work_dirs,
                               author=self,
                               chat_history={self.name: prompt.get()})

    while prompt and cur_round <= MAX_ROUND:
      self._generate_fuzz_target(prompt, result_history, build_result,
                                 cur_round)

      self._validate_fuzz_target(cur_round, build_result)
      prompt = self._advice_fuzz_target(build_result, cur_round)
      cur_round += 1

    return build_result
