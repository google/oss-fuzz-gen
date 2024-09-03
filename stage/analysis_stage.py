"""Analyzing the evaluation output of the fuzz target and build script."""
from results import Result
from stage.base_stage import BaseStage


class AnalysisStage(BaseStage):

  def execute(self, prev_stage_results: list[Result]) -> Result:
    # A placeholder for now.
    return prev_stage_results[-1]
