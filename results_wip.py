# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The data structure of all result kinds."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from experiment import textcov
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs


class FuzzTargetResult(Enum):
    """Error types for fuzz target analysis.
    
    These categories represent different kinds of errors that can occur
    during fuzzing:
    
    - NORM_*: Normal situations (no issues)
    - FP_*: False positives (issues with fuzzing infrastructure)
    - CRASH_*: Real crashes (actual bugs detected)
    - GEN_*: General problems
    - COV_*: Coverage issues
    """
    # Normal Situations (No Issues)
    NORM_NOT_APPLICABLE = auto()
    NORM_NO_SEMANTIC_ERR = auto()

    # False Positives (FP) - Issues with the fuzzing targets
    FP_NEAR_INIT_CRASH = auto()  # Crashes immediately at runtime
    FP_TARGET_CRASH = auto()  # Crashes caused by fuzz target code
    FP_MEMLEAK = auto()  # Memory leaks in the fuzz target
    FP_OOM = auto()  # Out of memory errors in the fuzz target
    FP_TIMEOUT = auto()  # Fuzz target timed out

    # Not Security-Related Crashes
    NON_SEC_CRASH_NULL_DEREF = auto()  # Null pointer dereference
    NON_SEC_CRASH_SIGNAL = auto()  # Abort with signal, indicating assertion violations
    NON_SEC_CRASH_EXIT = auto()  # Controlled exit without memory corruption

    # General Problems
    GEN_LOG_MESS_UP = auto()  # Issues with fuzzing logs
    GEN_OVERWRITE_CONST = auto()  # Fuzz target modified const data

    # Coverage Issues
    COV_NO_INCREASE = auto()  # No code coverage increase

    @classmethod
    def from_string(self, value: str) -> 'FuzzTargetResult':
        """Convert legacy string error types to enum values."""
        mapping = {
            '-': self.NORM_NOT_APPLICABLE,
            'NO_SEMANTIC_ERR': self.NORM_NO_SEMANTIC_ERR,
            'FP_NEAR_INIT_CRASH': self.FP_NEAR_INIT_CRASH,
            'FP_TARGET_CRASH': self.FP_TARGET_CRASH,
            'FP_MEMLEAK': self.FP_MEMLEAK,
            'FP_OOM': self.FP_OOM,
            'FP_TIMEOUT': self.FP_TIMEOUT,
            'NULL_DEREF': self.NON_SEC_CRASH_NULL_DEREF,
            'SIGNAL': self.NON_SEC_CRASH_SIGNAL,
            'EXIT': self.NON_SEC_CRASH_EXIT,
            'LOG_MESS_UP': self.GEN_LOG_MESS_UP,
            'OVERWRITE_CONST': self.GEN_OVERWRITE_CONST,
            'NO_COV_INCREASE': self.COV_NO_INCREASE,
        }
        return mapping.get(value, self.NORM_NOT_APPLICABLE)

    def to_string(self) -> str:
        """Convert enum values to legacy string error types for backward compatibility."""
        mapping = {
            self.NORM_NOT_APPLICABLE: '-',
            self.NORM_NO_SEMANTIC_ERR: 'NO_SEMANTIC_ERR',
            self.FP_NEAR_INIT_CRASH: 'FP_NEAR_INIT_CRASH',
            self.FP_TARGET_CRASH: 'FP_TARGET_CRASH',
            self.FP_MEMLEAK: 'FP_MEMLEAK',
            self.FP_OOM: 'FP_OOM',
            self.FP_TIMEOUT: 'FP_TIMEOUT',
            self.NON_SEC_CRASH_NULL_DEREF: 'NULL_DEREF',
            self.NON_SEC_CRASH_SIGNAL: 'SIGNAL',
            self.NON_SEC_CRASH_EXIT: 'EXIT',
            self.GEN_LOG_MESS_UP: 'LOG_MESS_UP',
            self.GEN_OVERWRITE_CONST: 'OVERWRITE_CONST',
            self.COV_NO_INCREASE: 'NO_COV_INCREASE',
        }
        return mapping.get(self, self.NORM_NOT_APPLICABLE)

    def get_error_desc(self, crash_symptom_desc: str = '') -> str:
        """Returns one sentence error description used in fix prompt."""
        mapping = {
            self.GEN_LOG_MESS_UP:
                'Overlong fuzzing log.',
            self.FP_NEAR_INIT_CRASH:
                f'Fuzzing crashed immediately at runtime ({crash_symptom_desc})'
                ', indicating fuzz target code for invoking the function under'
                ' test is incorrect or unrobust.',
            self.FP_TARGET_CRASH:
                f'Fuzzing has crashes ({crash_symptom_desc}) caused by fuzz '
                'target code, indicating its usage for the function under '
                'test is incorrect or unrobust.',
            self.FP_MEMLEAK:
                'Memory leak detected, indicating some memory was not freed '
                'by the fuzz target.',
            self.FP_OOM:
                'Out-of-memory error detected, suggesting the fuzz target '
                'incorrectly allocates too much memory or has a memory leak.',
            self.FP_TIMEOUT:
                'Fuzz target timed out at runtime, indicating its usage for '
                'the function under test is incorrect or unrobust.',
            self.COV_NO_INCREASE:
                'No code coverage increasement, indicating the fuzz target'
                ' ineffectively invokes the function under test.',
            self.NON_SEC_CRASH_NULL_DEREF:
                'Accessing a null pointer, indicating improper parameter '
                'initialization or incorrect function usages in the fuzz target.',
            self.NON_SEC_CRASH_SIGNAL:
                'Abort with signal, indicating the fuzz target has violated some '
                'assertion in the project, likely due to improper parameter '
                'initialization or incorrect function usages.',
            self.NON_SEC_CRASH_EXIT:
                'Fuzz target exited in a controlled manner without showing any '
                'sign of memory corruption, likely due to the fuzz target is not '
                'well designed to effectively find memory corruption '
                'vulnerability in the function-under-test.',
            self.GEN_OVERWRITE_CONST:
                'Fuzz target modified a const data. To fix this, ensure that all '
                'input data passed to the fuzz target is treated as read-only '
                'and not modified. Copy the input data to a separate buffer if '
                'any modifications are necessary.',
        }

        return mapping.get(self, self.NORM_NOT_APPLICABLE)


@dataclass
class BuildInfo:
    """Information about a fuzz target build."""
    compiles: bool = False
    log_path: str = ""
    errors: List[str] = field(default_factory=list)
    binary_exists: bool = False
    is_function_referenced: bool = False
    fuzz_target_source: str = ""
    build_script_source: str = ""

    @property
    def success(self) -> bool:
        """Whether the build was successful (compiles and produces usable binary)."""
        return self.compiles and self.binary_exists and self.is_function_referenced

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'compiles': self.compiles,
            'build_success': self.success,
            'log_path': self.log_path,
            'errors': self.errors,
            'binary_exists': self.binary_exists,
            'is_function_referenced': self.is_function_referenced,
            'fuzz_target_source': self.fuzz_target_source,
            'build_script_source': self.build_script_source,
        }


@dataclass
class RunInfo:
    """Information about a fuzz target run."""
    crashes: bool = False
    log_path: str = ""
    corpus_path: str = ""
    reproducer_path: str = ""

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'crashes': self.crashes,
            'log_path': self.log_path,
            'corpus_path': self.corpus_path,
            'reproducer_path': self.reproducer_path,
        }


@dataclass
class CrashAnalysis:
    """Analysis of a crash during fuzzing."""
    true_bug: bool = False
    insight: str = ""
    run_error: str = ""
    crash_func: Optional[Dict] = None
    crash_symptom: str = ""
    crash_stacks: List[List[str]] = field(default_factory=list)
    crash_info: str = ""

    @property
    def has_err(self) -> bool:
        """Whether there is a crash error."""
        return bool(self.crash_symptom or self.run_error)

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'true_bug': self.true_bug,
            'insight': self.insight,
            'run_error': self.run_error,
            'crash_func': self.crash_func or {},
            'crash_symptom': self.crash_symptom,
            'crash_stacks': self.crash_stacks,
            'crash_info': self.crash_info,
            'has_err': self.has_err,
        }


@dataclass
class CoverageAnalysis:
    """Analysis of code coverage from fuzzing."""
    coverage: float
    line_coverage_diff: float
    coverage_report_path: str
    textcov_diff: Optional[textcov.Textcov]
    cov_pcs: int
    total_pcs: int
    improvement_required: bool = False
    insight: str = ""
    suggestions: str = ""

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'improve_required': self.improvement_required,
            'insight': self.insight,
            'suggestions': self.suggestions,
        }


@dataclass
class AnalysisInfo:
    """Analysis of fuzzing results including crash and coverage information."""
    crash_analysis: Optional[CrashAnalysis] = None
    coverage_analysis: Optional[CoverageAnalysis] = None
    error_type: Optional[FuzzTargetResult] = None

    @property
    def success(self) -> bool:
        """Whether the analysis indicates success (no errors)."""
        crash_success = not (self.crash_analysis and self.crash_analysis.has_err)
        coverage_success = not (self.coverage_analysis and self.coverage_analysis.improvement_required)
        return crash_success and coverage_success

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'crash_analysis': self.crash_analysis.to_dict() if self.crash_analysis else {},
            'coverage_analysis': self.coverage_analysis.to_dict() if self.coverage_analysis else {},
            'error_type': self.error_type.to_string() if self.error_type else '',
            'success': self.success,
        }


@dataclass
class Result:
    """A benchmark generation result with all associated information."""
    benchmark: Benchmark
    work_dirs: WorkDirs
    trial: int
    iteration: int = 0
    build_info: Optional[BuildInfo] = None
    run_info: Optional[RunInfo] = None
    analysis_info: Optional[AnalysisInfo] = None
    author: Any = None
    chat_history: Dict = field(default_factory=dict)

    def is_build_successful(self) -> bool:
        """Check if the build was successful."""
        return self.build_info is not None and self.build_info.success

    def is_run_successful(self) -> bool:
        """Check if the run was successful (did not crash)."""
        return self.run_info is not None and not self.run_info.crashes

    def is_semantic_error(self) -> bool:
        """Check if there was a semantic error."""
        return self.analysis_info is not None and not self.analysis_info.success

    def get_fuzz_target_source(self) -> str:
        """Get the fuzz target source code."""
        return self.build_info.fuzz_target_source if self.build_info else ""

    def get_build_script_source(self) -> str:
        """Get the build script source code."""
        return self.build_info.build_script_source if self.build_info else ""

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        result = {
            'function_signature': self.benchmark.function_signature,
            'project': self.benchmark.project,
            'project_commit': self.benchmark.commit,
            'project_language': self.benchmark.language,
            'trial': self.trial,
            'fuzz_target_source': self.get_fuzz_target_source(),
            'build_script_source': self.get_build_script_source(),
            'author': self.author.name if self.author else "",
            'chat_history': self.chat_history,
        }

        if self.build_info:
            result.update(self.build_info.to_dict())

        if self.run_info:
            result.update(self.run_info.to_dict())

        if self.analysis_info:
            result.update(self.analysis_info.to_dict())

        return result


class TrialResult:
    """All history results for a trial of a benchmark in an experiment."""
    benchmark: Benchmark
    trial: int
    work_dirs: WorkDirs
    result_history: list[Result]

    def __init__(
            self,
            benchmark: Benchmark,
            trial: int,
            work_dirs: WorkDirs,
            result_history: Optional[list[Result]] = None,
    ) -> None:
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
    def best_analysis_result(self) -> Optional[Result]:
        """Last Result with AnalysisInfo in trial, prefer crashed and a non-semantic error."""
        # 1. Crashed for a non-semantic error
        for result in self.result_history[::-1]:
            analysis = result.analysis_info
            if analysis and not result.is_semantic_error() and result.run_info and result.run_info.crashes:
                return result

        # 2. Crashed
        for result in self.result_history[::-1]:
            if result.run_info and result.run_info.crashes:
                return result

        # 3. Result with AnalysisInfo
        for result in self.result_history[::-1]:
            if result.analysis_info:
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
            if result.analysis_info:
                analysis_info = result.analysis_info
                if analysis_info.coverage_analysis and analysis_info.coverage_analysis.line_coverage_diff > max_cov_diff:
                    max_cov_diff = analysis_info.coverage_analysis.line_coverage_diff
                    best_result = result
        if best_result:
            return best_result

        max_cov = -1
        for result in self.result_history:
            if result.analysis_info:
                analysis_info = result.analysis_info
                if analysis_info.coverage_analysis and analysis_info.coverage_analysis.coverage > max_cov:
                    max_cov = analysis_info.coverage_analysis.coverage
                    best_result = result
        if best_result:
            return best_result

        for result in self.result_history:
            if result.is_build_successful():
                return result

        # If no result has coverage info, return the last result
        return self.result_history[-1]

    @property
    def fuzz_target_source(self) -> str:
        """The best fuzz target source code."""
        result = self.best_result
        return result.get_fuzz_target_source() if result else ""

    @property
    def build_script_source(self) -> str:
        """The best build script source code."""
        result = self.best_result
        return result.get_build_script_source() if result else ""

    @property
    def author(self) -> Any:
        """The author of the best result."""
        result = self.best_result
        return result.author if result else None

    @property
    def chat_history(self) -> dict:
        """The chat history of the best result."""
        result = self.best_result
        return result.chat_history if result else {}

    @property
    def build_success(self) -> bool:
        """True if there is any build success."""
        return any(result.is_build_successful() for result in self.result_history)

    @property
    def crashes(self) -> bool:
        """True if there is any runtime crash."""
        return any(
            result.run_info and result.run_info.crashes
            for result in self.result_history
        )

    @property
    def is_semantic_error(self) -> bool:
        """True if the best result has a semantic error."""
        result = self.best_analysis_result
        return result.is_semantic_error() if result else False

    @property
    def error_type(self) -> Optional[FuzzTargetResult]:
        """Error type of the best result."""
        result = self.best_analysis_result
        return result.analysis_info.error_type if result and result.analysis_info else None

    def to_dict(self) -> Dict:
        """Convert to a dictionary for serialization."""
        return {
            'function_signature': self.function_signature,
            'project': self.project,
            'project_commit': self.project_commit,
            'project_language': self.project_language,
            'trial': self.trial,
            'fuzz_target_source': self.fuzz_target_source,
            'build_script_source': self.build_script_source,
            'author': self.author.name if self.author else '',
            'chat_history': self.chat_history,
            'build_success': self.build_success,
            'crashes': self.crashes,
            'error_type': self.error_type.to_string() if self.error_type else '',
            'is_semantic_error': self.is_semantic_error,
        }


class BenchmarkResult:
    """All trial results for a benchmark in an experiment."""
    benchmark: Benchmark
    work_dirs: WorkDirs
    trial_results: list[TrialResult]

    def __init__(
            self,
            benchmark: Benchmark,
            work_dirs: WorkDirs,
            trial_results: Optional[list[TrialResult]] = None,
    ) -> None:
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
        return sum(1 for trial in self.trial_results if trial.build_success)

    @property
    def build_success_rate(self) -> float:
        """Build success Ratio."""
        if not self.trial_count:
            return 0.0
        return self.build_success_count / self.trial_count

    @property
    def crash_rate(self) -> float:
        """True if there is any run crash not caused by semantic error."""
        if not self.trial_count:
            return 0.0

        crash_count = sum(
            1 for trial in self.trial_results
            if trial.crashes and not trial.is_semantic_error
        )
        return crash_count / self.trial_count

    @property
    def coverage(self) -> float:
        """Max coverage across all trials."""
        if not self.trial_results:
            return 0.0

        return max((
            trial.best_result.analysis_info.coverage_analysis.coverage
            for trial in self.trial_results
            if trial.best_result and hasattr(trial.best_result,
                                             'analysis_info') and trial.best_result.analysis_info.coverage_analysis
        ), default=0.0)

    @property
    def line_coverage_diff(self) -> float:
        """Max line coverage diff across all trials."""
        if not self.trial_results:
            return 0.0

        return max((
            trial.best_result.analysis_info.coverage_analysis.line_coverage_diff
            for trial in self.trial_results
            if trial.best_result and hasattr(trial.best_result,
                                             'analysis_info') and trial.best_result.analysis_info.coverage_analysis
        ), default=0.0)

    @property
    def line_coverage_report(self) -> str:
        """Return the coverage report path for the trial with highest line coverage diff."""
        if not self.trial_results:
            return ''

        max_diff = -1.0
        report_path = ''

        for trial in self.trial_results:
            if not (
                    trial.best_result and trial.best_result.analysis_info and trial.best_result.analysis_info.coverage_analysis):
                coverage_analysis = trial.best_result.analysis_info.coverage_analysis
                if coverage_analysis.line_coverage_diff > max_diff:
                    max_diff = coverage_analysis.line_coverage_diff
                    report_path = coverage_analysis.coverage_report_path

        return report_path

    @property
    def textcov_diff(self) -> textcov.Textcov:
        """Merge all textcov diffs from all trials."""
        all_textcov = textcov.Textcov()

        for trial in self.trial_results:
            if not (
                    trial.best_result and trial.best_result.analysis_info and trial.best_result.analysis_info.coverage_analysis):
                coverage_analysis = trial.best_result.analysis_info.coverage_analysis
                if coverage_analysis.textcov_diff:
                    all_textcov.merge(coverage_analysis.textcov_diff)

        return all_textcov
