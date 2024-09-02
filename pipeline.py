"""The fuzzing main pipeline."""
import argparse

from result_classes import Result
from stage.analysis_stage import AnalysisStage
from stage.evaluation_stage import EvalationStage
from stage.writing_stage import WritingStage


class Pipeline():
  """The fuzzing main pipeline, with 3 iterative stages."""

  def __init__(self, args: argparse.Namespace):
    self.args = args
    self.writing_stage: WritingStage = WritingStage(args)
    self.evaluation_stage: EvalationStage = EvalationStage(args)
    self.analysis_stage: AnalysisStage = AnalysisStage(args)

  def _terminate(self, results: list[Result]) -> bool:
    """Validates if the termination conditions have been satisfied."""
    return bool(results and results[-1].fuzz_target_source)

  def _execute_one_cycle(self, results: list[Result]) -> None:
    """Executes the stages once."""
    results.append(self.writing_stage.execute(prev_stage_results=results))

  def execute(self, results: list[Result]) -> list[Result]:
    """Executes the stages iteratively."""
    while not self._terminate(results=results):
      self._execute_one_cycle(results=results)
    return results
