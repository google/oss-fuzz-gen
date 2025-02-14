"""The fuzzing main pipeline."""
import argparse
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from results import AnalysisResult, BuildResult, Result, RunResult
from stage.analysis_stage import AnalysisStage
from stage.execution_stage import ExecutionStage
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
               trial: int,
               writing_stage_agents: Optional[list[BaseAgent]] = None,
               execution_stage_agents: Optional[list[BaseAgent]] = None,
               analysis_stage_agents: Optional[list[BaseAgent]] = None):
    self.args = args
    self.trial = trial
    self.logger = logger.get_trial_logger(trial=trial)
    self.logger.debug('Pipeline Initialized')
    self.writing_stage: WritingStage = WritingStage(args, trial,
                                                    writing_stage_agents)
    self.execution_stage: ExecutionStage = ExecutionStage(
        args, trial, execution_stage_agents)
    self.analysis_stage: AnalysisStage = AnalysisStage(args, trial,
                                                       analysis_stage_agents)

  def _terminate(self, result_history: list[Result], cycle_count: int) -> bool:
    """Validates if the termination conditions have been satisfied."""
    if not cycle_count:
      return False

    last_result = result_history[-1]
    if cycle_count > 5:
      self.logger.warning('[Cycle %d] Terminate after 5 cycles: %s',
                          cycle_count, result_history)
      return True

    if not isinstance(last_result, AnalysisResult):
      self.logger.warning('[Cycle %d] Last result is not AnalysisResult: %s',
                          cycle_count, result_history)
      return True

    if last_result.success:
      self.logger.info('[Cycle %d] Generation succeeds: %s', cycle_count,
                       result_history)
      return True

    self.logger.info('[Cycle %d] Generation continues: %s', cycle_count,
                     result_history)
    return False

  def _execute_one_cycle(self, result_history: list[Result],
                         cycle_count: int) -> None:
    """Executes the stages once."""
    self.logger.info('[Cycle %d] Initial result is %s', cycle_count,
                     result_history[-1])
    result_history.append(
        self.writing_stage.execute(result_history=result_history))
    if (not isinstance(result_history[-1], BuildResult) or
        not result_history[-1].success):
      self.logger.warning('[Cycle %d] Build failure, skipping the rest steps',
                          cycle_count)
      return

    result_history.append(
        self.execution_stage.execute(result_history=result_history))
    if (not isinstance(result_history[-1], RunResult) or
        not result_history[-1].log_path):
      self.logger.warning('[Cycle %d] Run failure, skipping the rest steps',
                          cycle_count)
      return

    result_history.append(
        self.analysis_stage.execute(result_history=result_history))

    self.logger.info('[Cycle %d] Analysis result %s: %s', cycle_count,
                     result_history[-1].success, result_history[-1])

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
    self.logger.debug('Pipeline starts')
    cycle_count = 0
    while not self._terminate(result_history=result_history,
                              cycle_count=cycle_count):
      cycle_count += 1
      self._execute_one_cycle(result_history=result_history,
                              cycle_count=cycle_count)

    final_result = result_history[-1]
    self.logger.write_result(result_status_dir=final_result.work_dirs.status,
                             result=final_result)
    return result_history
