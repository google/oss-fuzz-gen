"""The fuzzing main pipeline."""
import argparse
from typing import Optional

from agent.base_agent import BaseAgent
from logger import Logger
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

  def __init__(self,
               args: argparse.Namespace,
               writing_stage_agents: Optional[list[BaseAgent]] = None,
               evaluation_stage_agents: Optional[list[BaseAgent]] = None,
               analysis_stage_agents: Optional[list[BaseAgent]] = None,
               logger: Optional[Logger] = None):
    self.args = args
    self.logger = logger or Logger(__name__)
    self.writing_stage: WritingStage = WritingStage(args, writing_stage_agents,
                                                    logger)
    self.evaluation_stage: EvalationStage = EvalationStage(
        args, evaluation_stage_agents, logger)
    self.analysis_stage: AnalysisStage = AnalysisStage(args,
                                                       analysis_stage_agents,
                                                       logger)

  def _terminate(self, result_history: list[Result]) -> bool:
    """Validates if the termination conditions have been satisfied."""
    return bool(result_history and len(result_history) > 1)

  def _execute_one_cycle(self, result_history: list[Result]) -> None:
    """Executes the stages once."""
    result_history.append(
        self.writing_stage.execute(result_history=result_history))

  def execute(self, result_history: list[Result]) -> list[Result]:
    """
    Runs the fuzzing pipeline iteratively to assess and refine the fuzz target.
    1. Writing Stage refines the fuzz target and its build script using insights
    from the previous cycle.
    2. Evaluation Stage measures the performance of the revised fuzz target.
    3. Analysis Stage examines the evaluation results to guide the next cycle's
    improvements.
    The process repeats until the termination conditions are met.
    """
    while not self._terminate(result_history=result_history):
      self._execute_one_cycle(result_history=result_history)
    final_result = result_history[-1]
    self.logger.write_result(result_status_dir=final_result.work_dirs.status,
                             result=final_result)
    return result_history
