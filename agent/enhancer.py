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
from agent.prototyper import Prototyper
#from experiment.workdir import WorkDirs
from llm_toolkit.prompt_builder import (DefaultTemplateBuilder,
                                        JvmErrorFixingBuilder)
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, Result


class Enhancer(Prototyper):
  """The Agent to refine a compilable fuzz target for higher coverage."""

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
