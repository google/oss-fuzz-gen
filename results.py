"""The data structure of all result kinds."""
import dataclasses
import os
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
  _repr_exclude = {'_repr_exclude', 'chat_history'}
  function_analysis: Optional['FunctionAnalysisResult']

  def __init__(
      self,
      benchmark: Benchmark,
      trial: int,
      work_dirs: WorkDirs,
      fuzz_target_source: str = '',
      build_script_source: str = '',
      author: Any = None,
      chat_history: Optional[dict] = None,
      default_success: bool = False,
      function_analysis: Optional['FunctionAnalysisResult'] = None) -> None:
    self.benchmark = benchmark
    self.trial = trial
    self.work_dirs = work_dirs
    self.fuzz_target_source = fuzz_target_source
    self.build_script_source = build_script_source
    self.author = author
    self.chat_history = chat_history or {}
    self.default_success = default_success
    self.function_analysis = function_analysis
    self.token_usage = None  # Will be set by workflow if available

  def __repr__(self) -> str:
    attributes = [
        f'{k}={v!r}' for k, v in vars(self).items()
        if k not in self._repr_exclude
    ]
    return f'{self.__class__.__name__}({", ".join(attributes)})'

  @property
  def success(self):
    return self.default_success

  def to_dict(self) -> dict:
    result = {
        'function_signature': self.benchmark.function_signature,
        'project': self.benchmark.project,
        'project_commit': self.benchmark.commit,
        'project_language': self.benchmark.language,
        'trial': self.trial,
        'fuzz_target_source': self.fuzz_target_source,
        'build_script_source': self.build_script_source,
        'author': self.author.name if self.author else '',
        'chat_history': self.chat_history,
    }
    if self.token_usage:
      result['token_usage'] = self.token_usage
    return result

# TODO: Make this class an attribute of Result, avoid too many attributes in one
# class.
class BuildResult(Result):
  """A benchmark generation result with build info."""
  compiles: bool  # Build success/failure.
  compile_error: str  # Build error message.
  compile_log: str  # Build full output.
  binary_exists: bool  # Fuzz target binary generated successfully.
  is_function_referenced: bool  # Fuzz target references function-under-test.
  _repr_exclude = Result._repr_exclude | {'compile_log', 'compile_error'}

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               compiles: bool = False,
               compile_error: str = '',
               compile_log: str = '',
               binary_exists: bool = False,
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
    self.binary_exists = binary_exists
    self.is_function_referenced = is_function_referenced

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'compiles': self.compiles,
        'compile_error': self.compile_error,
        'compile_log': self.compile_log,
        'binary_exists': self.binary_exists,
        'is_function_referenced': self.is_function_referenced,
    }

  @property
  def success(self):
    return self.compiles and self.binary_exists and self.is_function_referenced

# TODO: Make this class an attribute of Result, avoid too many attributes in one
# class.
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
  sanitizer: str
  textcov_diff: Optional[textcov.Textcov]
  log_path: str
  corpus_path: str
  coverage_report_path: str
  cov_pcs: int
  total_pcs: int
  _repr_exclude = BuildResult._repr_exclude | {'textcov_diff'}
  err_type: str
  crash_sypmtom: str
  crash_stacks: Optional[list[list[str]]]

  def __init__(
      self,
      benchmark: Benchmark,
      trial: int,
      work_dirs: WorkDirs,
      compiles: bool = False,
      compile_error: str = '',
      compile_log: str = '',
      binary_exists: bool = False,
      is_function_referenced: bool = False,
      crashes: bool = False,  # Runtime crash.
      run_error: str = '',  # Runtime crash error message.
      crash_func: Optional[dict] = None,
      run_log: str = '',  # Full fuzzing output.
      coverage_summary: Optional[dict] = None,
      coverage: float = 0.0,
      line_coverage_diff: float = 0.0,
      textcov_diff: Optional[textcov.Textcov] = None,
      reproducer_path: str = '',
      artifact_path: str = '',
      sanitizer: str = '',
      log_path: str = '',
      corpus_path: str = '',
      coverage_report_path: str = '',
      cov_pcs: int = 0,
      total_pcs: int = 0,
      err_type: str = SemanticCheckResult.NOT_APPLICABLE,
      crash_sypmtom: str = '',
      crash_stacks: Optional[list[list[str]]] = None,
      fuzz_target_source: str = '',
      build_script_source: str = '',
      author: Any = None,
      chat_history: Optional[dict] = None) -> None:
    super().__init__(benchmark, trial, work_dirs, compiles, compile_error,
                     compile_log, binary_exists, is_function_referenced,
                     fuzz_target_source, build_script_source, author,
                     chat_history)
    self.crashes = crashes
    self.run_error = run_error
    self.crash_func = crash_func or {}
    self.run_log = run_log
    self.coverage_summary = coverage_summary or {}
    self.coverage = coverage
    self.line_coverage_diff = line_coverage_diff
    self.reproducer_path = reproducer_path
    self.artifact_path = artifact_path
    self.sanitizer = sanitizer
    self.textcov_diff = textcov_diff
    self.log_path = log_path
    self.corpus_path = corpus_path
    self.coverage_report_path = coverage_report_path
    self.cov_pcs = cov_pcs
    self.total_pcs = total_pcs
    self.err_type = err_type
    self.crash_sypmtom = crash_sypmtom
    self.crash_stacks = crash_stacks or []

  @property
  def artifact_name(self) -> str:
    return os.path.basename(self.artifact_path)

  def to_dict(self) -> dict:
    return super().to_dict() | {
        'crashes':
            self.crashes,
        'run_error':
            self.run_error,
        'crash_func':
            self.crash_func or {},
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
        'err_type':
            self.err_type,
        'crash_sypmtom':
            self.crash_sypmtom,
        'crash_stacks':
            self.crash_stacks,
    }

  # TODO(dongge): Define success property to show if the fuzz target was run.

class CrashResult(Result):
  """The fuzzing run-time result with crash info."""
  stacktrace: str
  true_bug: bool  # True/False positive crash
  insight: str  # Reason and fixes for crashes

  def __init__(self,
               *args,
               stacktrace: str = '',
               true_bug: bool = False,
               insight: str = '',
               **kwargs):
    super().__init__(*args, **kwargs)
    self.stacktrace = stacktrace
    self.true_bug = true_bug
    self.insight = insight

  def to_dict(self) -> dict:
    return {
        'stacktrace': self.stacktrace,
        'true_bug': self.true_bug,
        'insight': self.insight,
    }

class CoverageResult():
  """The fuzzing run-time result with code coverage info."""
  improve_required: bool = False
  insight: str = ''  # Reason and fixes for low coverage
  suggestions: str = ''  # Suggestions to fix fuzz target.
  _repr_exclude = set()

  def to_dict(self) -> dict:
    return {
        'improve_required': self.improve_required,
        'insights': self.insight,
        'suggestions': self.suggestions
    }

  def __repr__(self) -> str:
    attributes = [
        f'{k}={v!r}' for k, v in vars(self).items()
        if k not in self._repr_exclude
    ]
    return f'{self.__class__.__name__}({", ".join(attributes)})'

class CrashContextResult():
  """Analysis result of the context of the crashing function."""
  feasible: bool
  analysis: str
  source_code_evidence: str
  recommendations: str

  def __init__(self,
               feasible: bool = False,
               analysis: str = '',
               source_code_evidence: str = '',
               recommendations: str = ''):
    self.feasible = feasible
    self.analysis = analysis
    self.source_code_evidence = source_code_evidence
    self.recommendations = recommendations

  def to_dict(self) -> dict:
    return {
        'feasible': self.feasible,
        'analysis': self.analysis,
        'source_code_evidence': self.source_code_evidence,
        'recommendations': self.recommendations,
    }

  @staticmethod
  def from_dict(data: Any) -> Optional['CrashContextResult']:
    """Creates a CrashContextResult from a dictionary."""

    if not isinstance(data,
                      dict) or 'feasible' not in data or 'analysis' not in data:
      return None

    return CrashContextResult(feasible=data.get('feasible', False),
                              analysis=data.get('analysis', ''),
                              source_code_evidence=data.get(
                                  'source_code_evidence', ''),
                              recommendations=data.get('recommendations', ''))

# TODO: Make this class an attribute of Result, avoid too many attributes in one
# class.
class AnalysisResult(Result):
  """Analysis of the fuzzing run-time result."""
  run_result: RunResult
  semantic_result: Optional[SemanticCheckResult]
  crash_result: Optional[CrashResult]
  crash_context_result: Optional[CrashContextResult]
  coverage_result: Optional[CoverageResult]

  def __init__(self,
               author: Any,
               run_result: RunResult,
               semantic_result: Optional[SemanticCheckResult] = None,
               crash_result: Optional[CrashResult] = None,
               crash_context_result: Optional[CrashContextResult] = None,
               coverage_result: Optional[CoverageResult] = None,
               chat_history: Optional[dict] = None,
               default_success: bool = False) -> None:
    super().__init__(run_result.benchmark, run_result.trial,
                     run_result.work_dirs, run_result.fuzz_target_source,
                     run_result.build_script_source, author, chat_history,
                     default_success)
    self.run_result = run_result
    self.semantic_result = semantic_result
    self.crash_result = crash_result
    self.crash_context_result = crash_context_result
    self.coverage_result = coverage_result

  def to_dict(self) -> dict:
    return self.run_result.to_dict() | {
        'semantic_result':
            self.semantic_result.to_dict() if self.semantic_result else {},
        'crash_result':
            self.crash_result.to_dict() if self.crash_result else {},
        'crash_context_result':
            self.crash_context_result.to_dict()
            if self.crash_context_result else {},
        'coverage_result':
            self.coverage_result.to_dict() if self.coverage_result else {},
    }

  # TODO(maoyi): maybe we should redefine success property or
  # rename the property
  @property
  def success(self) -> bool:
    if self.semantic_result:
      return not self.semantic_result.has_err
    if self.coverage_result:
      return not self.coverage_result.improve_required
    if self.crash_context_result:
      return self.crash_context_result.feasible
    if self.crash_result:
      return self.crash_result.true_bug
    return False

  @property
  def crashes(self) -> bool:
    return self.run_result.crashes

  @property
  def coverage(self) -> float:
    return self.run_result.coverage

  @property
  def line_coverage_diff(self) -> float:
    return self.run_result.line_coverage_diff

  @property
  def run_log(self) -> str:
    return self.run_result.run_log

  @property
  def log_path(self) -> str:
    return self.run_result.log_path

class TrialResult:
  """All history results for a trial of a benchmark in an experiment."""
  benchmark: Benchmark
  trial: int
  work_dirs: WorkDirs
  result_history: list[Result]

  def __init__(self,
               benchmark: Benchmark,
               trial: int,
               work_dirs: WorkDirs,
               result_history: Optional[list[Result]] = None) -> None:
    self.benchmark = benchmark
    self.trial = trial
    self.work_dirs = work_dirs
    self.result_history = result_history or []

  @property
  def function_signature(self) -> str:
    """Function signature of the benchmark."""
    return self.benchmark.function_signature

  @property
  def project(self) -> str:
    """Project name of the benchmark."""
    return self.benchmark.project

  @property
  def project_commit(self) -> str:
    """Project commit of the benchmark."""
    return self.benchmark.commit or ''

  @property
  def project_language(self) -> str:
    """Project language of the benchmark."""
    return self.benchmark.language

  @property
  def best_analysis_result(self) -> Optional[AnalysisResult]:
    """Last AnalysisResult in trial, prefer crashed and a non-semantic error."""
    # 1. Crashed for a non-semantic error
    for result in self.result_history[::-1]:
      #TODO(dongge): Refine this logic for coverage
      if (isinstance(result, AnalysisResult) and result.crashes):
        if result.crash_context_result and result.crash_context_result.feasible:
          return result
        if result.crash_result and result.crash_result.true_bug:
          return result

    # 2. Crashed
    for result in self.result_history[::-1]:
      if isinstance(result, AnalysisResult) and result.crashes:
        return result

    # 3. AnalysisResult
    for result in self.result_history[::-1]:
      if isinstance(result, AnalysisResult):
        return result
    return None

  @property
  def best_result(self) -> Result:
    """Best result in trial based on coverage."""
    # Preference order:
    #   1. Highest coverage diff (AnalysisResult)
    #   2. Highest coverage diff (RunResult)
    #   3. Highest coverage (AnalysisResult)
    #   3. Highest coverage (RunResult)
    #   4. Last Build success (BuildResult)
    #   5. Last Result
    best_result = None

    max_cov_diff = 0
    for result in self.result_history:
      if (isinstance(result, (RunResult, AnalysisResult)) and
          result.line_coverage_diff >= max_cov_diff):
        max_cov_diff = result.line_coverage_diff
        best_result = result
    if best_result:
      return best_result

    max_cov = 0
    for result in self.result_history:
      if (isinstance(result, (RunResult, AnalysisResult)) and
          result.coverage >= max_cov):
        max_cov = result.coverage
        best_result = result
    if best_result:
      return best_result

    for result in self.result_history[::-1]:
      if isinstance(result, BuildResult) and result.success:
        return result

    return self.result_history[-1]

  @property
  def fuzz_target_source(self) -> str:
    """The best fuzz target source code."""
    result = self.best_result
    if isinstance(result, AnalysisResult):
      return result.run_result.fuzz_target_source
    return self.best_result.fuzz_target_source

  @property
  def build_script_source(self) -> str:
    """The best build script source code."""
    result = self.best_result
    if isinstance(result, AnalysisResult):
      return result.run_result.build_script_source
    return self.best_result.build_script_source

  @property
  def author(self) -> Any:
    """The author of the best result."""
    return self.best_result.author

  @property
  def chat_history(self) -> dict:
    """The chat history of the best result."""
    return self.best_result.chat_history

  @property
  def build_success(self) -> bool:
    """True if there is any build success."""
    return any(result.success
               for result in self.result_history
               if isinstance(result, BuildResult))

  @property
  def crashes(self) -> bool:
    """True if there is any runtime crash."""
    return any(result.crashes
               for result in self.result_history
               if isinstance(result, RunResult))

  @property
  def coverage(self) -> float:
    """Max line coverage diff."""
    return max((result.coverage
                for result in self.result_history
                if isinstance(result, RunResult)),
               default=0)

  @property
  def line_coverage_diff(self) -> float:
    """Max line coverage diff."""
    return max((result.line_coverage_diff
                for result in self.result_history
                if isinstance(result, RunResult)),
               default=0)

  @property
  def cov_pcs(self) -> int:
    """Log path of the best result if it is RunResult."""
    return max((result.cov_pcs
                for result in self.result_history
                if isinstance(result, RunResult)),
               default=0)

  @property
  def total_pcs(self) -> int:
    """Log path of the best result if it is RunResult."""
    return max((result.total_pcs
                for result in self.result_history
                if isinstance(result, RunResult)),
               default=0)

  @property
  def line_coverage_report(self) -> str:
    """Max line coverage diff report."""
    for result in self.result_history:
      if not isinstance(result, RunResult):
        continue
      if result.line_coverage_diff == self.line_coverage_diff:
        return result.coverage_report_path
    return ''

  @property
  def textcov_diff(self) -> textcov.Textcov:
    """Sum textcov diff."""
    all_textcov = textcov.Textcov()
    for result in self.result_history:
      if isinstance(result, RunResult) and result.textcov_diff:
        all_textcov.merge(result.textcov_diff)
    return all_textcov

  @property
  def run_error(self) -> str:
    """Run error of the best result if it is RunResult."""
    result = self.best_result
    if isinstance(result, RunResult):
      return result.run_error
    if isinstance(result, AnalysisResult):
      return result.run_result.run_error
    return ''

  @property
  def run_log(self) -> str:
    """Run log of the best result if it is RunResult."""
    result = self.best_result
    if isinstance(result, (RunResult, AnalysisResult)):
      return result.run_log
    return ''

  @property
  def log_path(self) -> str:
    """Log path of the best result if it is RunResult."""
    result = self.best_result
    if isinstance(result, (RunResult, AnalysisResult)):
      return result.log_path
    return ''

  @property
  def is_semantic_error(self) -> bool:
    """Validates if the best AnalysisResult has semantic error."""
    result = self.best_analysis_result
    if result:
      if result.crash_context_result:
        return not result.crash_context_result.feasible
      if result.crash_result:
        return not result.crash_result.true_bug
    return False

  @property
  def semantic_error(self) -> str:
    """Semantic error type of the best AnalysisResult."""
    result = self.best_analysis_result
    if result and result.semantic_result:
      return result.semantic_result.type
    return '-'

  def to_dict(self) -> dict:
    result = {
        'trial':
            self.trial,
        'function_signature':
            self.function_signature,
        'project':
            self.project,
        'project_commit':
            self.project_commit,
        'project_language':
            self.project_language,
        'fuzz_target_source':
            self.fuzz_target_source,
        'build_script_source':
            self.build_script_source,
        'author':
            self.author.name if self.author else '',
        'chat_history':
            self.chat_history,
        'compiles':
            self.build_success,
        'crashes':
            self.crashes,
        'coverage':
            self.coverage,
        'line_coverage_diff':
            self.line_coverage_diff,
        'cov_pcs':
            self.cov_pcs,
        'total_pcs':
            self.total_pcs,
        'line_coverage_report':
            self.line_coverage_report,
        'textcov_diff':
            dataclasses.asdict(self.textcov_diff) if self.textcov_diff else '',
        'run_error':
            self.run_error,
        'run_log':
            self.run_log,
        'log_path':
            self.log_path,
        'is_semantic_error':
            self.is_semantic_error,
        'semantic_error':
            self.semantic_error,
    }
    
    # Include token_usage if available
    if self.best_result and hasattr(self.best_result, 'token_usage') and self.best_result.token_usage:
      result['token_usage'] = self.best_result.token_usage
    
    return result

class BenchmarkResult:
  """All trial results for a benchmark in an experiment."""
  benchmark: Benchmark
  work_dirs: WorkDirs
  trial_results: list[TrialResult]

  def __init__(self,
               benchmark: Benchmark,
               work_dirs: WorkDirs,
               trial_results: Optional[list[TrialResult]] = None) -> None:
    self.benchmark = benchmark
    self.work_dirs = work_dirs
    self.trial_results = trial_results or []

  @property
  def trial_count(self) -> int:
    """Total number of trials."""
    return len(self.trial_results)

  @property
  def build_success_count(self) -> int:
    """Build success count."""
    return sum(result.build_success for result in self.trial_results)

  @property
  def build_success_rate(self) -> float:
    """Build success Ratio."""
    if self.trial_count == 0:
      return 0
    return self.build_success_count / self.trial_count

  @property
  def crash_rate(self) -> float:
    """True if there is any run crash not caused by semantic error."""
    if self.trial_count == 0:
      return 0
    return sum(
        result.crashes for result in self.trial_results) / self.trial_count

  @property
  def coverage(self) -> float:
    """Max line coverage diff."""
    return max((result.coverage for result in self.trial_results), default=0)

  @property
  def line_coverage_diff(self) -> float:
    """Max line coverage diff."""
    return max((result.line_coverage_diff for result in self.trial_results),
               default=0)

  @property
  def line_coverage_report(self) -> str:
    """Max line coverage diff report."""
    for result in self.trial_results:
      if result.line_coverage_diff == self.line_coverage_diff:
        return result.line_coverage_report
    return ''

  @property
  def max_coverage_sample(self) -> str:
    """Fuzz target source code of the trial with max coverage."""
    for result in self.trial_results:
      if result.coverage == self.coverage:
        return result.fuzz_target_source
    return ''

  @property
  def max_coverage_diff_sample(self) -> str:
    """Fuzz target source code of the trial with max coverage diff."""
    for result in self.trial_results:
      if result.line_coverage_diff == self.line_coverage_diff:
        return result.fuzz_target_source
    return ''

  @property
  def textcov_diff(self) -> textcov.Textcov:
    """Sum textcov diff."""
    all_textcov = textcov.Textcov()
    for result in self.trial_results:
      all_textcov.merge(result.textcov_diff)
    return all_textcov

class FunctionAnalysisResult:
  """The result of the function analyzer."""
  description: str
  function_signature: str
  project_name: str
  requirements: str
  function_analysis_path: str

  def __init__(self,
               description: str,
               requirements: str,
               function_signature: str,
               project_name: str,
               function_analysis_path: str = ''):
    self.description = description
    self.requirements = requirements
    self.function_signature = function_signature
    self.project_name = project_name
    self.function_analysis_path = function_analysis_path

  def to_dict(self) -> dict:
    return {
        'description': self.description,
        'requirements': self.requirements,
        'function_analysis_path': self.function_analysis_path,
        'function_signature': self.function_signature,
        'project_name': self.project_name,
    }

  @staticmethod
  def from_dict(data: Any) -> Optional['FunctionAnalysisResult']:
    """Creates a FunctionAnalysisResult from a dictionary."""
    if not isinstance(
        data, dict
    ) or 'function_signature' not in data or 'project_name' not in data or 'description' not in data or 'requirements' not in data:
      return None

    return FunctionAnalysisResult(
        description=data.get('description', ''),
        function_signature=data.get('function_signature', ''),
        project_name=data.get('project_name', ''),
        requirements=data.get('requirements', ''),
        function_analysis_path=data.get('function_analysis_path', ''))
