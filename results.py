"""The data structure of all result kinds."""
from typing import Any, Optional

from experiment import textcov
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

  def to_dict(self) -> dict:
    return {
        'function_signature': self.benchmark.function_signature,
        'project': self.benchmark.project,
        'project_commit': self.benchmark.commit,
        'project_language': self.benchmark.language,
        'trial': self.trial,
        'fuzz_target_source': self.fuzz_target_source,
        'build_script_source': self.build_script_source,
    }


class BuildResult(Result):
  """A benchmark generation result with build info."""

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               status: bool = False,
               error: str = '',
               full_log: str = '',
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               agent_dialogs: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, fuzz_target_source,
                     build_script_source, author, agent_dialogs)
    self.status: bool = status  # Build success/failure.
    self.error: str = error  # Build error message.
    self.full_log: str = full_log  # Build full output.

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'compiles': self.status,
        'compile_error': self.error,
        'compile_log': self.full_log,
    }


class RunResult(BuildResult):
  """The fuzzing run-time result info."""

  def __init__(
      self,
      benchmark: Benchmark,
      trial: int,
      work_dirs: WorkDirs,
      status: bool = False,  # Runtime crash.
      error: str = '',  # Runtime crash error message.
      full_log: str = '',  # Full fuzzing output.
      coverage_summary: Optional[dict] = None,
      coverage: float = 0.0,
      line_coverage_diff: float = 0.0,
      textcov_diff: Optional[textcov.Textcov] = None,
      reproducer_path: str = '',
      log_path: str = '',
      corpus_path: str = '',
      coverage_report_path: str = '',
      cov_pcs: int = 0,
      total_pcs: int = 0,
      fuzz_target_source: str = '',
      build_script_source: str = '',
      author: Any = None,
      agent_dialogs: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, status, error, full_log,
                     fuzz_target_source, build_script_source, author,
                     agent_dialogs)
    self.coverage_summary: dict = coverage_summary or {}
    self.coverage: float = coverage
    self.line_coverage_diff: float = line_coverage_diff
    self.reproducer_path: str = reproducer_path
    self.textcov_diff: Optional[textcov.Textcov] = textcov_diff
    self.log_path: str = log_path
    self.corpus_path: str = corpus_path
    self.coverage_report_path: str = coverage_report_path
    self.cov_pcs: int = cov_pcs
    self.total_pcs: int = total_pcs

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'crashes': self.status,
        'crash_error': self.error,
        'crash_log': self.full_log,
        'coverage_summary': self.coverage_summary,
        'coverage': self.coverage,
        'line_coverage_diff': self.line_coverage_diff,
        'log_path': self.log_path,
        'corpus_path': self.corpus_path,
        'coverage_report_path': self.coverage_report_path,
        'cov_pcs': self.cov_pcs,
        'total_pcs': self.total_pcs,
    }


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
