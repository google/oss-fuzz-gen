"""A module to evaluate the fuzz target prototype.
Use it as a usual module locally, or as script in cloud builds.
"""
from results import Result
from stage.base_stage import BaseStage


class EvalationStage(BaseStage):
  """The module to measure the code coverage and run-time crashes performance of
  the fuzz target."""

  def execute(self, result_history: list[Result]) -> Result:
    # A placeholder for now.
    return result_history[-1]
