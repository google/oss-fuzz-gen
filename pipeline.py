"""The fuzzing main pipeline."""
import argparse

from results import Result
from stage.analysis_stage import AnalysisStage
from stage.evaluation_stage import EvalationStage
from stage.writing_stage import WritingStage


class Pipeline():
  """The fuzzing main pipeline, consisting of three iterative stages:
    1. Writing stage generates or refines the fuzz target and its associated
       build script to improve code coverage and enhance bug-finding
       capabilities for the function under test.
    2. Evaluation stage assesses the fuzz target's performance by measuring
       code coverage and detecting runtime crashes.
    3. Analysis stage examines the results from the evaluation stage, extracting
       insights from the coverage and crash data to suggest improvements for the
       writing stage in the next iteration.
    """

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
    """
    Runs the fuzzing pipeline iteratively to assess and refine the fuzz target.
    1. Writing Stage refines the fuzz target and its build script using insights
    from the previous cycle.
    2. Evaluation Stage measures the performance of the revised fuzz target.
    3. Analysis Stage examines the evaluation results to guide the next cycle's
    improvements.
    The process repeats until the termination conditions are met.
    """
    while not self._terminate(results=results):
      self._execute_one_cycle(results=results)
    return results
