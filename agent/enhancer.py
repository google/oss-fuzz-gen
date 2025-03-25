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
from llm_toolkit.prompt_builder import EnhancerTemplateBuilder, JvmFixingBuilder
from llm_toolkit.prompts import Prompt
from results import AnalysisResult, BuildResult, Result


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

    last_build_result = None
    for result in results[::-1]:
      if isinstance(result, BuildResult):
        last_build_result = result
        break
    if not last_build_result:
      logger.error('Unable to find the last build result in Enhancer : %s',
                   results,
                   trial=self.trial)
      return Prompt()

    if benchmark.language == 'jvm':
      # TODO: Do this in a separate agent for JVM coverage.
      builder = JvmFixingBuilder(self.llm, benchmark,
                                 last_result.run_result.fuzz_target_source, [])
      prompt = builder.build([], None, None)
    else:
      # TODO(dongge): Refine this logic.
      if last_result.semantic_result:
        error_desc, errors = last_result.semantic_result.get_error_info()
        builder = EnhancerTemplateBuilder(self.llm, benchmark,
                                          last_build_result, error_desc, errors)
      else:
        builder = EnhancerTemplateBuilder(
            self.llm,
            benchmark,
            last_build_result,
            coverage_result=last_result.coverage_result)
      prompt = builder.build(example_pair=[],
                             tool_guides=self.inspect_tool.tutorial(),
                             project_dir=self.inspect_tool.project_dir)
      # TODO: A different file name/dir.
      prompt.save(self.args.work_dirs.prompt)

    return prompt
