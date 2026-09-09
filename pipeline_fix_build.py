# Copyright 2026 Google LLC
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
"""Pipeline for OSS-Fuzz project build repair experiments."""

import argparse
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from results import BuildResult, Result, TrialResult
from stage.writing_stage import WritingStage


class FixBuildPipeline:
  """Runs only the writing/build-repair stage for project-level build fixes."""

  def __init__(self,
               args: argparse.Namespace,
               trial: int,
               writing_stage_agents: Optional[list[BaseAgent]] = None):
    self.args = args
    self.trial = trial
    self.logger = logger.get_trial_logger(trial=trial)
    self.writing_stage = WritingStage(args, trial, writing_stage_agents)

  def _update_status(self,
                     result_history: list[Result],
                     finished: bool = False) -> None:
    trial_result = TrialResult(benchmark=result_history[-1].benchmark,
                               trial=self.trial,
                               work_dirs=result_history[-1].work_dirs,
                               result_history=result_history)
    self.logger.write_result(
        result_status_dir=trial_result.best_result.work_dirs.status,
        result=trial_result,
        finished=finished)

  def execute(self, result_history: list[Result]) -> list[Result]:
    """Executes a single build-repair attempt and records report state."""
    self._update_status(result_history=result_history)
    build_result = self.writing_stage.execute(result_history=result_history,
                                              cycle_count=1)
    result_history.append(build_result)
    if not isinstance(build_result, BuildResult):
      self.logger.warning('Fix-build agent returned non-build result: %s',
                          build_result)
    self._update_status(result_history=result_history, finished=True)
    return result_history
