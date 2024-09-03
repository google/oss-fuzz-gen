"""Evaluating the fuzz target and build script."""
from results import Result
from stage.base_stage import BaseStage


class EvalationStage(BaseStage):

  def execute(self, result_history: list[Result]) -> Result:
    # A placeholder for now.
    return result_history[-1]
