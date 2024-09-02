"""Evaluating the fuzz target and build script."""
from result_classes import Result
from stage.base_stage import BaseStage


class EvalationStage(BaseStage):

  def execute(self, prev_stage_results: list[Result]) -> Result:
    # A placeholder for now.
    return prev_stage_results[-1]
