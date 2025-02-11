"""The data structure of all result kinds."""
import dataclasses
from typing import Any, Optional

from experiment import textcov
from experiment.benchmark import Benchmark
from experiment.fuzz_target_error import SemanticCheckResult
from experiment.workdir import WorkDirs


class Result:
  """A benchmark generation result."""
  benchmark: Benchmark
  trial: int
  work_dirs: WorkDirs
  fuzz_target_source: str
  build_script_source: str
  author: Any
  chat_history: dict

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               chat_history: Optional[dict] = None) -> None:
    self.benchmark = benchmark
    self.trial = trial
    self.work_dirs = work_dirs
    self.fuzz_target_source = fuzz_target_source
    self.build_script_source = build_script_source
    self.author = author
    self.chat_history = chat_history or {}

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
        'author': str(self.author),
        'chat_history': self.chat_history,
    }


class BuildResult(Result):
  """A benchmark generation result with build info."""
  compiles: bool  # Build success/failure.
  compile_error: str  # Build error message.
  compile_log: str  # Build full output.
  is_function_referenced: bool  # Fuzz target references function-under-test.

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               compiles: bool = False,
               compile_error: str = '',
               compile_log: str = '',
               is_function_referenced: bool = False,
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               chat_history: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, fuzz_target_source,
                     build_script_source, author, chat_history)
    self.compiles = compiles
    self.compile_error = compile_error
    self.compile_log = compile_log
    self.is_function_referenced = is_function_referenced

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'compiles': self.success,
        'compile_error': self.compile_error,
        'compile_log': self.compile_log,
        'is_function_referenced': self.is_function_referenced,
    }

  @property
  def success(self):
    return self.compiles and self.is_function_referenced


class RunResult(BuildResult):
  """The fuzzing run-time result info."""
  crashes: bool
  run_error: str
  run_log: str
  coverage_summary: dict
  coverage: float
  line_coverage_diff: float
  reproducer_path: str
  textcov_diff: Optional[textcov.Textcov]
  log_path: str
  corpus_path: str
  coverage_report_path: str
  cov_pcs: int
  total_pcs: int

  def __init__(
      self,
      benchmark: Benchmark,
      trial: int,
      work_dirs: WorkDirs,
      compiles: bool = False,
      compile_error: str = '',
      compile_log: str = '',
      is_function_referenced: bool = False,
      crashes: bool = False,  # Runtime crash.
      run_error: str = '',  # Runtime crash error message.
      run_log: str = '',  # Full fuzzing output.
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
      chat_history: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, compiles, compile_error,
                     compile_log, is_function_referenced, fuzz_target_source,
                     build_script_source, author, chat_history)
    self.crashes = crashes
    self.run_error = run_error
    self.run_log = run_log
    self.coverage_summary = coverage_summary or {}
    self.coverage = coverage
    self.line_coverage_diff = line_coverage_diff
    self.reproducer_path = reproducer_path
    self.textcov_diff = textcov_diff
    self.log_path = log_path
    self.corpus_path = corpus_path
    self.coverage_report_path = coverage_report_path
    self.cov_pcs = cov_pcs
    self.total_pcs = total_pcs

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'crashes':
            self.crashes,
        'run_error':
            self.run_error,
        'run_log':
            self.run_log,
        'coverage_summary':
            self.coverage_summary or {},
        'coverage':
            self.coverage,
        'line_coverage_diff':
            self.line_coverage_diff,
        'reproducer_path':
            self.reproducer_path,
        'textcov_diff':
            dataclasses.asdict(self.textcov_diff) if self.textcov_diff else '',
        'log_path':
            self.log_path,
        'corpus_path':
            self.corpus_path,
        'coverage_report_path':
            self.coverage_report_path,
        'cov_pcs':
            self.cov_pcs,
        'total_pcs':
            self.total_pcs,
    }

  # TODO(dongge): Define success property to show if the fuzz target was run.


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


class AnalysisResult(Result):
  """Analysis of the fuzzing run-time result."""
  run_result: RunResult
  semantic_result: SemanticCheckResult
  crash_result: Optional[CrashResult]
  coverage_result: Optional[CoverageResult]

  def __init__(self,
               author: str,
               run_result: RunResult,
               semantic_result: SemanticCheckResult,
               crash_result: Optional[CrashResult] = None,
               coverage_result: Optional[CoverageResult] = None,
               chat_history: Optional[dict] = None) -> None:
    super().__init__(run_result.benchmark, run_result.trial,
                     run_result.work_dirs, run_result.fuzz_target_source,
                     run_result.build_script_source, author, chat_history)
    self.run_result = run_result
    self.semantic_result = semantic_result
    self.crash_result = crash_result
    self.coverage_result = coverage_result

  def to_dict(self) -> dict:
    return self.run_result.to_dict() | {
        'semantic_result': self.semantic_result.to_dict(),
        'crash_result': self.crash_result,
        'coverage_result': self.coverage_result,
    }

  @property
  def success(self):
    return not self.semantic_result.has_err


class ExperimentResult:
  """All result history of a benchmark during a trial experiment."""
  history_results: list[Result]

  def __init__(self, history_results: Optional[list[Result]] = None) -> None:
    self.history_results = history_results or []

  def __repr__(self) -> str:
    """Summarizes results for the report."""
    raise NotImplementedError
