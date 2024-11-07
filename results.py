"""The data structure of all result kinds."""
import dataclasses
from typing import Any, Optional

from experiment import textcov
from experiment.benchmark import Benchmark
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

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               compiles: bool = False,
               compile_error: str = '',
               compile_log: str = '',
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               chat_history: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, fuzz_target_source,
                     build_script_source, author, chat_history)
    self.compiles = compiles
    self.compile_error = compile_error
    self.compile_log = compile_log

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'compiles': self.compiles,
        'compile_error': self.compile_error,
        'compile_log': self.compile_log,
    }

  @property
  def success(self):
    return self.compiles


class RunResult(BuildResult):
  """The fuzzing run-time result info."""
  crashes: bool
  run_error: str
  crash_func: dict
  run_log: str
  coverage_summary: dict
  coverage: float
  line_coverage_diff: float
  reproducer_path: str
  artifact_path: str
  artifact_name: str
  sanitizer: str
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
      crashes: bool = False,
      run_error: str = '',
      crash_func: Optional[dict] = None,
      run_log: str = '',  # Full fuzzing output.
      coverage_summary: Optional[dict] = None,
      coverage: float = 0.0,
      line_coverage_diff: float = 0.0,
      textcov_diff: Optional[textcov.Textcov] = None,
      reproducer_path: str = '',
      artifact_path: str = '',
      artifact_name: str = '',
      sanitizer: str = '',
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
                     compile_log, fuzz_target_source, build_script_source,
                     author, chat_history)
    self.crashes = crashes
    self.run_error = run_error
    self.crash_func = crash_func or {}
    self.run_log = run_log
    self.coverage_summary = coverage_summary or {}
    self.coverage = coverage
    self.line_coverage_diff = line_coverage_diff
    self.reproducer_path = reproducer_path
    self.artifact_path = artifact_path
    self.artifact_name = artifact_name
    self.sanitizer = sanitizer
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
        'crash_func':
            self.crash_func,
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
        'artifact_path':
            self.artifact_path,
        'artifact_name':
            self.artifact_name,
        'sanitizer':
            self.sanitizer,
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

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               compiles: bool = False,
               compile_error: str = '',
               compile_log: str = '',
               crashes: bool = False,
               run_error: str = '',
               crash_func: Optional[dict] = None,
               run_log: str = '',
               coverage_summary: Optional[dict] = None,
               coverage: float = 0.0,
               line_coverage_diff: float = 0.0,
               textcov_diff: Optional[textcov.Textcov] = None,
               reproducer_path: str = '',
               artifact_path: str = '',
               artifact_name: str = '',
               sanitizer: str = '',
               log_path: str = '',
               corpus_path: str = '',
               coverage_report_path: str = '',
               cov_pcs: int = 0,
               total_pcs: int = 0,
               fuzz_target_source: str = '',
               build_script_source: str = '',
               author: Any = None,
               chat_history: Optional[dict] = None,
               stacktrace: str = '',
               true_bug: bool = False,
               insight: str = '') -> None:
    super().__init__(benchmark, trial, work_dirs, compiles, compile_error,
                     compile_log, crashes, run_error, crash_func, run_log,
                     coverage_summary, coverage, line_coverage_diff,
                     textcov_diff, reproducer_path, artifact_path,
                     artifact_name, sanitizer, log_path, corpus_path,
                     coverage_report_path, cov_pcs, total_pcs,
                     fuzz_target_source, build_script_source, author,
                     chat_history)
    self.stacktrace = stacktrace
    self.true_bug = true_bug
    self.insight = insight

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'stacktrace': self.stacktrace,
        'true_bug': self.true_bug,
        'insight': self.insight,
    }


class CoverageResult(RunResult):
  """The fuzzing run-time result with code coverage info."""
  coverage_percentage: float
  coverage_reports: dict[str, str]  # {source_file: coverage_report_content}
  insight: str  # Reason and fixes for low coverage


class ExperimentResult:
  """All result history of a benchmark during a trial experiment."""
  history_results: list[Result]

  def __init__(self, history_results: Optional[list[Result]] = None) -> None:
    self.history_results = history_results or []

  def __repr__(self) -> str:
    """Summarizes results for the report."""
    raise NotImplementedError
