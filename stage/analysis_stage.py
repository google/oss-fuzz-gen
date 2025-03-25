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
"""The Analysis Stage class for examining the performance of fuzz targets. This
stage is responsible for categorizing run-time crashes and detecting untested
code blocks."""
from results import Result, RunResult
from stage.base_stage import BaseStage


class AnalysisStage(BaseStage):
  """Analyzes the runtime performance of fuzz targets and suggests improvements.
  This stage examines whether crashes are due to bugs in the fuzz target or
  if there are significant code blocks left uncovered. Based on this analysis,
  it provides recommendations for refining the fuzz target in subsequent stages.
  Additionally, it prepares to terminate the experiment if the fuzz target
  crashes due to a bug in the project under test or if all major code paths have
  been sufficiently covered."""

  def execute(self, result_history: list[Result]) -> Result:
    """Selects agent based on run result and executes it."""
    self.logger.info('Analysis Stage')
    last_result = result_history[-1]
    assert isinstance(last_result, RunResult)
    if last_result.crashes:
      agent = self.get_agent(agent_name='SemanticAnalyzer')
    else:
      agent = self.get_agent(agent_name='CoverageAnalyzer')
    analysis_result = agent.execute(result_history)

    # TODO(dongge): Save logs and more info into workdir.
    self.logger.write_chat_history(analysis_result)
    self.logger.debug('Analysis stage completed with with result:\n%s',
                      analysis_result)
    return analysis_result
