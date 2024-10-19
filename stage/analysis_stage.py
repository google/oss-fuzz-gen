"""The Analysis Stage class for examining the performance of fuzz targets. This
stage is responsible for categorizing run-time crashes and detecting untested
code blocks."""
import os
from typing import cast

from results import CrashResult, Result, RunResult
from stage.base_stage import BaseStage


class AnalysisStage(BaseStage):
  """Analyzes the runtime performance of fuzz targets and suggests improvements.
  This stage examines whether crashes are due to bugs in the fuzz target or
  if there are significant code blocks left uncovered. Based on this analysis,
  it provides recommendations for refining the fuzz target in subsequent stages.
  Additionally, it prepares to terminate the experiment if the fuzz target
  crashes due to a bug in the project under test or if all major code paths have
  been sufficiently covered."""

  def _analyze_crash(self, result_history: list[Result]) -> Result:
    """Analyzes a runtime crash."""
    agent = self.get_agent('CrashAnalyzer')
    if self.args.cloud_experiment_name:
      return self._execute_agent_cloud(agent, result_history)
    return agent.execute(result_history)

  def _analyze_coverage(self, result_history: list[Result]) -> Result:
    """Analyzes the coverage."""
    pass

  def execute(self, result_history: list[Result]) -> Result:
    """Executes the analysis stage."""
    last_result = result_history[-1]
    if not isinstance(last_result, RunResult):
      self.logger.error('CrashResult must follow a RunResult')
      raise TypeError

    # 1. Analyzing the runtime crash.
    agent_result = self._analyze_crash(result_history)

    crash_result = cast(CrashResult, agent_result)

    #TODO(fdt622): Save logs and more info into workdir.

    return crash_result
