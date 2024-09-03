"""The data structure of all result kinds."""
from typing import Any, Optional

from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs


class Result:
  """A benchmark generation result."""

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               agent_dialogs: Optional[dict] = None) -> None:
    self.benchmark: Benchmark = benchmark
    self.trial: int = trial
    self.work_dirs: WorkDirs = work_dirs
    self.fuzz_target_source: str = fuzz_target_source
    self.build_script_source: str = build_script_source
    self.author: Any = author
    # {'agent_name': LLM-Tool chat log}
    self.agent_dialogs: dict = agent_dialogs or {}

  def __repr__(self) -> str:
    return (f'{self.__class__.__name__}'
            f'({", ".join(f"{k}={v!r}" for k, v in vars(self).items())})')


class BuildResult(Result):
  """A benchmark generation result with build info."""

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               status: bool = False,
               error: str = '',
               full_log: str = '',
               insight: str = '',
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               agent_dialogs: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, fuzz_target_source,
                     build_script_source, author, agent_dialogs)
    self.status: bool = status  # Build success/failure.
    self.error: str = error  # Build error message.
    self.full_log: str = full_log  # Build full output.
    self.insight: str = insight  # Reason and fixes for build failure.


class RunResult(Result):
  """The fuzzing run-time result info."""
  status: bool  # Run success/failure
  error: str  # Run error message
  full_log: str  # Run full output


class CrashResult(RunResult):
  """The fuzzing run-time result with crash info."""
  stacktrace: str
  true_bug: bool  # True/False positive crash
  insight: str  # Reason and fixes for crashes


class CoverageResult(RunResult):
  """The fuzzing run-time result with code coverage info."""
  coverage_percentage: float
  coverage_reports: dict[str, str]  # {source_file: coverage_report_content}
  insight: str  # Reason and fixes for low coverage


class ExperimentResult:
  """All result history of a benchmark during a trial experiment."""

  def __init__(self, history_results: Optional[list[Result]] = None) -> None:
    self.history_results: list[Result] = history_results or []

  def __repr__(self) -> str:
    """Summarizes results for the report."""
    raise NotImplementedError
