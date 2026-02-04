# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License a
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
ResultManager for OSS-Fuzz SDK.

This module provides the central, authoritative repository for all fuzz
execution results, providing unified storage, retrieval, and analytics
capabilities."""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

# Import Benchmark from the real BenchmarkManager
from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager
from ossfuzz_py.errors import ResultCollectionError
from ossfuzz_py.history.build_history_manager import BuildHistoryManager
from ossfuzz_py.history.corpus_history_manager import CorpusHistoryManager
from ossfuzz_py.history.coverage_history_manager import CoverageHistoryManager
from ossfuzz_py.history.crash_history_manager import CrashHistoryManager

from . import textcov
from .results import AnalysisInfo, BuildInfo, Result, RunInfo

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.result_manager')


class ResultManager:
  """
  Central, authoritative repository for all fuzz execution results.

  This class serves as the unified interface for storing, retrieving,
  and analyzing fuzz execution results. It coordinates with HistoryManager
  subclasses to persist BuildInfo, RunInfo, and AnalysisInfo components and
  provides analytics capabilities to eliminate duplicate logic across the
  codebase.

  The ResultManager integrates seamlessly with the existing Builder/Runner
  pipeline, BenchmarkManager, and all HistoryManager classes.
  """

  def __init__(
      self,
      build_mgr: BuildHistoryManager,
      crash_mgr: CrashHistoryManager,
      corpus_mgr: CorpusHistoryManager,
      coverage_mgr: CoverageHistoryManager,
      benchmark_manager: Optional['BenchmarkManager'] = None,
  ) -> None:
    """
    Initialize ResultManager with required HistoryManager dependencies.

    Args:
        build_mgr: BuildHistoryManager for build result persistence
        crash_mgr: CrashHistoryManager for crash data persistence
        corpus_mgr: CorpusHistoryManager for corpus statistics persistence
        coverage_mgr: CoverageHistoryManager for coverage data persistence
        benchmark_manager: Optional BenchmarkManager for benchmark data
        retrieval
    """
    self.build_mgr = build_mgr
    self.crash_mgr = crash_mgr
    self.corpus_mgr = corpus_mgr
    self.coverage_mgr = coverage_mgr
    self.benchmark_manager = benchmark_manager
    self.logger = logger

  def store_result(self, benchmark_id: str, result: Result) -> None:
    """
    Store a Result by decomposing it into appropriate HistoryManager calls.

    This method takes a complete Result object and stores its components
    (BuildInfo, RunInfo, AnalysisInfo) through the appropriate HistoryManager
    subclasses to ensure proper data persistence and organization.

    Args:
        benchmark_id: Unique identifier for the benchmark
        result: Complete Result object to store

    Raises:
        ResultCollectionError: If storage fails
    """
    try:
      self.logger.info("Storing result for benchmark %s, trial %d",
                       benchmark_id, result.trial)

      # Store BuildInfo through BuildHistoryManager
      if result.build_info:
        build_data = self._convert_build_info_to_dict(result, benchmark_id)
        self.build_mgr.store_build_result(build_data)
        self.logger.debug("Stored build info for benchmark %s", benchmark_id)

      # Store crash data through CrashHistoryManager
      if result.run_info and result.run_info.crashes:
        crash_data = self._convert_run_info_to_crash_dict(result, benchmark_id)
        self.crash_mgr.store_crash(crash_data)
        self.logger.debug("Stored crash data for benchmark %s", benchmark_id)

      # Store corpus data through CorpusHistoryManager
      if result.run_info and result.run_info.corpus_path:
        corpus_data = self._convert_run_info_to_corpus_dict(
            result, benchmark_id)
        self.corpus_mgr.store_corpus_stats(corpus_data)
        self.logger.debug("Stored corpus data for benchmark %s", benchmark_id)

      # Store coverage data through CoverageHistoryManager
      if result.analysis_info and result.analysis_info.coverage_analysis:
        coverage_data = self._convert_analysis_info_to_coverage_dict(
            result, benchmark_id)
        self.coverage_mgr.store_coverage(coverage_data)
        self.logger.debug("Stored coverage data for benchmark %s", benchmark_id)

    except Exception as e:
      error_msg = (f"Failed to store result for benchmark {benchmark_id}: "
                   f"{str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def get_result(self, benchmark_id: str) -> Optional[Result]:
    """
    Retrieve the latest Result for a benchmark by reconstructing from
    HistoryManagers.

    This method queries all HistoryManager subclasses to reconstruct the mos
    recent complete Result object for the specified benchmark.

    Args:
        benchmark_id: Unique identifier for the benchmark

    Returns:
        Latest Result object or None if no results found

    Raises:
        ResultCollectionError: If retrieval fails
    """
    try:
      self.logger.debug("Retrieving latest result for benchmark %s",
                        benchmark_id)

      # Get latest build data
      build_history = self.build_mgr.get_build_history(limit=1)
      build_info = None
      latest_build_data = None
      if build_history:
        latest_build_data = build_history[0]
        build_info = self._convert_dict_to_build_info(latest_build_data)

      # Get latest crash data
      crash_history = self.crash_mgr.get_crash_history(limit=1)
      run_info = None
      if crash_history:
        run_info = self._convert_dict_to_run_info(crash_history[0])

      # Get latest coverage data
      coverage_history = self.coverage_mgr.get_coverage_history(limit=1)
      analysis_info = None
      if coverage_history:
        analysis_info = self._convert_dict_to_analysis_info(coverage_history[0])

      # If no data found, return None
      if not any([build_info, run_info, analysis_info]):
        return None

      # Create benchmark for the result using BenchmarkManager
      benchmark = self._create_minimal_benchmark(benchmark_id)

      # Extract work_dirs and trial from the latest available data
      work_dirs = ""
      trial = 1
      if latest_build_data:
        work_dirs = latest_build_data.get('work_dirs', '')
        trial = latest_build_data.get('trial', 1)

      # Reconstruct Result objec
      result = Result(
          benchmark=benchmark,
          work_dirs=work_dirs,
          trial=trial,
          iteration=0,
          build_info=build_info,
          run_info=run_info,
          analysis_info=analysis_info,
      )

      self.logger.debug("Successfully retrieved result for benchmark %s",
                        benchmark_id)
      return result

    except Exception as e:
      error_msg = (f"Failed to retrieve result for benchmark {benchmark_id}: "
                   f"{str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def get_trial_result(self, benchmark_id: str,
                       trial_id: int) -> Optional[Result]:
    """
    Retrieve a specific trial Result for a benchmark.

    Args:
        benchmark_id: Unique identifier for the benchmark
        trial_id: Specific trial number to retrieve

    Returns:
        Result object for the specified trial or None if not found

    Raises:
        ResultCollectionError: If retrieval fails
    """
    try:
      self.logger.debug("Retrieving trial %d result for benchmark %s", trial_id,
                        benchmark_id)

      # Get build data for specific trial
      build_history = self.build_mgr.get_build_history(
          limit=100)  # Get more history to find trial
      build_info = None
      latest_build_data = None
      for build_data in build_history:
        latest_build_data = build_history[0]
        if build_data.get('trial') == trial_id and build_data.get(
            'benchmark_id') == benchmark_id:
          build_info = self._convert_dict_to_build_info(build_data)
          break

      # Get crash data for specific trial
      crash_history = self.crash_mgr.get_crash_history(limit=100)
      run_info = None
      for crash_data in crash_history:
        if crash_data.get('trial') == trial_id and crash_data.get(
            'benchmark_id') == benchmark_id:
          run_info = self._convert_dict_to_run_info(crash_data)
          break

      # Get coverage data for specific trial
      coverage_history = self.coverage_mgr.get_coverage_history(limit=100)
      analysis_info = None
      for coverage_data in coverage_history:
        if coverage_data.get('trial') == trial_id and coverage_data.get(
            'benchmark_id') == benchmark_id:
          analysis_info = self._convert_dict_to_analysis_info(coverage_data)
          break

      # If no data found for this trial, return None
      if not any([build_info, run_info, analysis_info]):
        self.logger.debug("No data found for trial %d of benchmark %s",
                          trial_id, benchmark_id)
        return None

      # Create benchmark for the result using BenchmarkManager
      benchmark = self._create_minimal_benchmark(benchmark_id)

      work_dirs = ""
      if latest_build_data:
        work_dirs = latest_build_data.get('work_dirs', '')

      # Reconstruct Result object for specific trial
      result = Result(
          benchmark=benchmark,
          work_dirs=work_dirs,
          trial=trial_id,
          iteration=0,
          build_info=build_info,
          run_info=run_info,
          analysis_info=analysis_info,
      )

      self.logger.debug(
          "Successfully retrieved trial %d result for benchmark %s", trial_id,
          benchmark_id)
      return result

    except Exception as e:
      error_msg = (f"Failed to retrieve trial {trial_id} result for "
                   f"benchmark {benchmark_id}: {str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def get_metrics(self, benchmark_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive metrics for a benchmark or all benchmarks.

    This method provides a unified interface for accessing all metrics
    as defined in the previous conversation, eliminating duplicate analytics
    logic.

    Args:
        benchmark_id: Optional benchmark ID. If None, returns aggregated metrics

    Returns:
        Dictionary containing comprehensive metrics

    Raises:
        ResultCollectionError: If metrics calculation fails
    """
    try:
      if benchmark_id:
        return self._get_benchmark_metrics(benchmark_id)
      return self._get_aggregated_metrics()

    except Exception as e:
      error_msg = f"Failed to calculate metrics: {str(e)}"
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def coverage_trend(self, benchmark_id: str, start_date: datetime,
                     end_date: datetime) -> Union[Any, List[Dict[str, Any]]]:
    """
    Return time-series coverage data as pandas DataFrame or list of dicts.

    Args:
        benchmark_id: Benchmark identifier
        start_date: Start date for trend analysis
        end_date: End date for trend analysis

    Returns:
        DataFrame with time-series coverage data if pandas available,
        otherwise list of dictionaries

    Raises:
        ResultCollectionError: If trend analysis fails
    """
    try:
      self.logger.debug("Calculating coverage trend for benchmark %s",
                        benchmark_id)

      # Get coverage history for the specified period
      coverage_history = self.coverage_mgr.get_coverage_history(
          start_date=start_date.isoformat(), end_date=end_date.isoformat())

      if not coverage_history:
        return pd.DataFrame()

      # Convert to DataFrame
      df = pd.DataFrame(coverage_history)
      if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.set_index('timestamp')
      return df

    except Exception as e:
      error_msg = (f"Failed to calculate coverage trend for benchmark "
                   f"{benchmark_id}: {str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def latest_successful_build(self, benchmark_id: str) -> Optional[Result]:
    """
    Return the most recent Result with successful build.

    Args:
        benchmark_id: Benchmark identifier

    Returns:
        Latest Result with successful build or None if not found

    Raises:
        ResultCollectionError: If retrieval fails
    """
    try:
      self.logger.debug("Finding latest successful build for benchmark %s",
                        benchmark_id)

      # Get build history and find the latest successful build
      build_history = self.build_mgr.get_build_history(
          limit=50)  # Check last 50 builds

      for build_data in build_history:
        if build_data.get('success', False):
          # Reconstruct Result for this successful build
          build_info = self._convert_dict_to_build_info(build_data)
          benchmark = self._create_minimal_benchmark(benchmark_id)

          return Result(
              benchmark=benchmark,
              work_dirs=build_data.get('work_dirs', ''),
              trial=build_data.get('trial', 1),
              build_info=build_info,
          )

      return None

    except Exception as e:
      error_msg = (f"Failed to find latest successful build for benchmark "
                   f"{benchmark_id}: {str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def get_build_success_rate(self, benchmark_id: str, days: int = 30) -> float:
    """
    Calculate build success rate over specified period.

    Args:
        benchmark_id: Benchmark identifier
        days: Number of days to analyze

    Returns:
        Build success rate as a float between 0.0 and 1.0

    Raises:
        ResultCollectionError: If calculation fails
    """
    try:
      self.logger.debug(
          "Calculating build success rate for benchmark %s over %d days",
          benchmark_id, days)

      # Calculate date range
      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      # Get build statistics for the specified period
      try:
        build_stats = self.build_mgr.get_build_statistics(
            start_date.isoformat(), end_date.isoformat())
      except TypeError:
        # Fallback if get_build_statistics doesn't accept date parameters
        build_stats = self.build_mgr.get_build_statistics()

      total_builds = build_stats.get('total_builds', 0)
      if total_builds == 0:
        return 0.0

      successful_builds = build_stats.get('successful_builds', 0)
      return successful_builds / total_builds

    except Exception as e:
      error_msg = (f"Failed to calculate build success rate for benchmark "
                   f"{benchmark_id}: {str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  def get_crash_summary(self,
                        benchmark_id: str,
                        days: int = 30) -> Dict[str, Any]:
    """
    Get crash statistics and analysis summary.

    Args:
        benchmark_id: Benchmark identifier
        days: Number of days to analyze

    Returns:
        Dictionary containing crash statistics and analysis

    Raises:
        ResultCollectionError: If calculation fails
    """
    try:
      self.logger.debug(
          "Calculating crash summary for benchmark %s over %d days",
          benchmark_id, days)

      # Calculate date range
      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      # Get crash statistics
      crash_stats = self.crash_mgr.get_crash_statistics(start_date.isoformat(),
                                                        end_date.isoformat())

      return crash_stats

    except Exception as e:
      error_msg = (f"Failed to calculate crash summary for benchmark "
                   f"{benchmark_id}: {str(e)}")
      self.logger.error(error_msg)
      raise ResultCollectionError(error_msg) from e

  # Private helper methods for data conversion

  def _calculate_corpus_stats(self, corpus_path: str) -> Dict[str, int]:
    """
    Calculate corpus statistics from the corpus directory.

    Args:
        corpus_path: Path to the corpus directory or file

    Returns:
        Dictionary with corpus_size, total_size_bytes, and new_files_coun
    """
    if not corpus_path:
      return {'corpus_size': 0, 'total_size_bytes': 0, 'new_files_count': 0}

    corpus_path_obj = Path(corpus_path)

    # Handle zip files (common for corpus storage)
    if corpus_path.endswith('.zip') and corpus_path_obj.exists():
      try:
        import zipfile
        with zipfile.ZipFile(corpus_path, 'r') as zip_file:
          file_list = zip_file.namelist()
          corpus_size = len([f for f in file_list if not f.endswith('/')])
          total_size_bytes = sum(
              zip_file.getinfo(f).file_size
              for f in file_list
              if not f.endswith('/'))
          return {
              'corpus_size': corpus_size,
              'total_size_bytes': total_size_bytes,
              'new_files_count':
                  corpus_size,  # All files are "new" for this calculation
          }
      except Exception as e:
        self.logger.warning("Failed to analyze zip corpus %s: %s", corpus_path,
                            e)
        return {'corpus_size': 0, 'total_size_bytes': 0, 'new_files_count': 0}

    # Handle directory
    if corpus_path_obj.is_dir():
      try:
        corpus_size = 0
        total_size_bytes = 0
        for file_path in corpus_path_obj.rglob('*'):
          if file_path.is_file():
            corpus_size += 1
            total_size_bytes += file_path.stat().st_size

        return {
            'corpus_size': corpus_size,
            'total_size_bytes': total_size_bytes,
            'new_files_count':
                corpus_size,  # All files are "new" for this calculation
        }
      except Exception as e:
        self.logger.warning("Failed to analyze directory corpus %s: %s",
                            corpus_path, e)
        return {'corpus_size': 0, 'total_size_bytes': 0, 'new_files_count': 0}

    # Handle single file
    if corpus_path_obj.is_file():
      try:
        file_size = corpus_path_obj.stat().st_size
        return {
            'corpus_size': 1,
            'total_size_bytes': file_size,
            'new_files_count': 1,
        }
      except Exception as e:
        self.logger.warning("Failed to analyze file corpus %s: %s", corpus_path,
                            e)
        return {'corpus_size': 0, 'total_size_bytes': 0, 'new_files_count': 0}

    # Path doesn't exist or is not accessible
    return {'corpus_size': 0, 'total_size_bytes': 0, 'new_files_count': 0}

  def _convert_build_info_to_dict(self, result: Result,
                                  benchmark_id: str) -> Dict[str, Any]:
    """Convert BuildInfo to dictionary format for BuildHistoryManager."""
    build_info = result.build_info
    if build_info is None:
      raise ValueError("BuildInfo is None")

    return {
        'benchmark_id': benchmark_id,
        'trial': result.trial,
        'iteration': result.iteration,
        'timestamp': datetime.now().isoformat(),
        'work_dirs': result.work_dirs,  # Store work_dirs for retrieval
        'success': build_info.success,
        'compiles': build_info.compiles,
        'compile_log': build_info.compile_log,
        'errors': build_info.errors,
        'binary_exists': build_info.binary_exists,
        'is_function_referenced': build_info.is_function_referenced,
        'fuzz_target_source': build_info.fuzz_target_source,
        'build_script_source': build_info.build_script_source,
    }

  def _convert_run_info_to_crash_dict(self, result: Result,
                                      benchmark_id: str) -> Dict[str, Any]:
    """Convert RunInfo to crash dictionary format for CrashHistoryManager."""
    run_info = result.run_info
    if run_info is None:
      raise ValueError("RunInfo is None")

    return {
        'benchmark_id': benchmark_id,
        'trial': result.trial,
        'iteration': result.iteration,
        'timestamp': datetime.now().isoformat(),
        'work_dirs': result.work_dirs,  # Store work_dirs for retrieval
        'crash_signature': run_info.crash_info or 'Unknown crash',
        'fuzzer_name': f"{benchmark_id}_trial_{result.trial}",
        'severity': 'UNKNOWN',  # Default severity
        'reproducible': not run_info.timeout,
        'stack_trace': run_info.crash_info,
        'error_message': run_info.error_message,
        'reproducer_path': run_info.reproducer_path,
        'run_log': run_info.run_log,  # Store run_log for retrieval
        'log_path': run_info.log_path,  # Store log_path for retrieval
    }

  def _convert_run_info_to_corpus_dict(self, result: Result,
                                       benchmark_id: str) -> Dict[str, Any]:
    """Convert RunInfo to corpus dictionary format for CorpusHistoryManager."""
    run_info = result.run_info
    if run_info is None:
      raise ValueError("RunInfo is None")

    # Calculate actual corpus statistics
    corpus_stats = self._calculate_corpus_stats(run_info.corpus_path)

    return {
        'benchmark_id': benchmark_id,
        'trial': result.trial,
        'iteration': result.iteration,
        'timestamp': datetime.now().isoformat(),
        'work_dirs': result.work_dirs,  # Store work_dirs for retrieval
        'fuzzer_name': f"{benchmark_id}_trial_{result.trial}",
        'corpus_path': run_info.corpus_path,
        'corpus_size': corpus_stats['corpus_size'],
        'total_size_bytes': corpus_stats['total_size_bytes'],
        'new_files_count': corpus_stats['new_files_count'],
    }

  def _convert_analysis_info_to_coverage_dict(
      self, result: Result, benchmark_id: str) -> Dict[str, Any]:
    """Convert AnalysisInfo to coverage dictionary format for
    CoverageHistoryManager."""
    analysis_info = result.analysis_info
    if analysis_info is None:
      raise ValueError("AnalysisInfo is None")

    coverage_analysis = analysis_info.coverage_analysis
    if coverage_analysis is None:
      raise ValueError("CoverageAnalysis is None")

    return {
        'benchmark_id': benchmark_id,
        'trial': result.trial,
        'iteration': result.iteration,
        'timestamp': datetime.now().isoformat(),
        'work_dirs': result.work_dirs,  # Store work_dirs for retrieval
        'fuzzer_name': f"{benchmark_id}_trial_{result.trial}",
        'line_coverage': coverage_analysis.line_coverage,
        'line_coverage_diff': coverage_analysis.line_coverage_diff,
        'coverage_report_path': coverage_analysis.coverage_report_path,
        'cov_pcs': coverage_analysis.cov_pcs,
        'total_pcs': coverage_analysis.total_pcs,
    }

  def _convert_dict_to_build_info(self, build_data: Dict[str,
                                                         Any]) -> BuildInfo:
    """Convert dictionary to BuildInfo object."""
    return BuildInfo(
        compiles=build_data.get('compiles', False),
        compile_log=build_data.get('compile_log', ''),
        errors=build_data.get('errors', []),
        binary_exists=build_data.get('binary_exists', False),
        is_function_referenced=build_data.get('is_function_referenced', False),
        fuzz_target_source=build_data.get('fuzz_target_source', ''),
        build_script_source=build_data.get('build_script_source', ''),
    )

  def _convert_dict_to_run_info(self, crash_data: Dict[str, Any]) -> RunInfo:
    """Convert dictionary to RunInfo object with cross-referenced data."""
    # Get additional data from other history managers
    benchmark_id = crash_data.get('benchmark_id', '')
    trial = crash_data.get('trial', 1)

    # Get corpus data for this benchmark/trial
    corpus_path = ''
    try:
      corpus_history = self.corpus_mgr.get_corpus_stats(limit=50)
      for corpus_entry in corpus_history:
        if (corpus_entry.get('benchmark_id') == benchmark_id and
            corpus_entry.get('trial') == trial):
          corpus_path = corpus_entry.get('corpus_path', '')
          break
    except Exception as e:
      self.logger.debug("Failed to retrieve corpus path: %s", e)

    # Get coverage data for this benchmark/trial
    cov_pcs, total_pcs, coverage_report_path = 0, 0, ''
    try:
      coverage_history = self.coverage_mgr.get_coverage_history(limit=50)
      for coverage_entry in coverage_history:
        if (coverage_entry.get('benchmark_id') == benchmark_id and
            coverage_entry.get('trial') == trial):
          cov_pcs = coverage_entry.get('cov_pcs', 0)
          total_pcs = coverage_entry.get('total_pcs', 0)
          coverage_report_path = coverage_entry.get('coverage_report_path', '')
          break
    except Exception as e:
      self.logger.debug("Failed to retrieve coverage data: %s", e)

    return RunInfo(
        crashes=True,  # If we have crash data, there was a crash
        run_log=crash_data.get('run_log', ''),
        corpus_path=corpus_path,
        reproducer_path=crash_data.get('reproducer_path', ''),
        timeout=not crash_data.get('reproducible',
                                   True),  # Invert reproducible flag
        error_message=crash_data.get('error_message', ''),
        cov_pcs=cov_pcs,
        total_pcs=total_pcs,
        crash_info=crash_data.get('stack_trace', ''),
        log_path=crash_data.get('log_path', ''),
        coverage_report_path=coverage_report_path,
    )

  def _convert_dict_to_analysis_info(
      self, coverage_data: Dict[str, Any]) -> AnalysisInfo:
    """Convert dictionary to AnalysisInfo object with enhanced data
    reconstruction."""
    from .results import CoverageAnalysis, CrashAnalysis

    coverage_analysis = CoverageAnalysis(
        line_coverage=coverage_data.get('line_coverage', 0.0),
        line_coverage_diff=coverage_data.get('line_coverage_diff', 0.0),
        coverage_report_path=coverage_data.get('coverage_report_path', ''),
        textcov_diff=self._reconstruct_textcov_diff(coverage_data),
        cov_pcs=coverage_data.get('cov_pcs', 0),
        total_pcs=coverage_data.get('total_pcs', 0),
    )

    # Try to get crash analysis data for the same benchmark/trial
    crash_analysis = None
    try:
      benchmark_id = coverage_data.get('benchmark_id', '')
      trial = coverage_data.get('trial', 1)
      crash_history = self.crash_mgr.get_crash_history(limit=50)
      for crash_entry in crash_history:
        if (crash_entry.get('benchmark_id') == benchmark_id and
            crash_entry.get('trial') == trial):
          crash_stacks_data = crash_entry.get('crash_stacks')
          crash_stacks = crash_stacks_data if isinstance(
              crash_stacks_data, list) else []
          crash_analysis = CrashAnalysis(
              true_bug=crash_entry.get('reproducible', False),
              crash_func=crash_entry.get('crash_func'),
              crash_stacks=crash_stacks,
          )
          break
    except Exception as e:
      self.logger.debug("Failed to retrieve crash analysis: %s", e)

    return AnalysisInfo(coverage_analysis=coverage_analysis,
                        crash_analysis=crash_analysis)

  def _reconstruct_textcov_diff(
      self, coverage_data: Dict[str, Any]) -> Optional['textcov.Textcov']:
    """
    Reconstruct textcov_diff from coverage data.

    This is a placeholder implementation. In a real scenario, this would
    parse coverage report files to reconstruct the textual coverage diff.
    """
    # For now, return None as this is a placeholder implementation
    # In a real implementation, this would parse the coverage report
    # and create a proper textcov.Textcov object
    # pylint: disable=unused-argument
    return None

  def _create_minimal_benchmark(self, benchmark_id: str) -> Benchmark:
    """Create a Benchmark object for Result reconstruction, using
    BenchmarkManager when available."""
    # Try to get full benchmark data from BenchmarkManager
    if self.benchmark_manager:
      try:
        existing_benchmark = self.benchmark_manager.get_benchmark(benchmark_id)
        if existing_benchmark:
          self.logger.debug(
              "Retrieved full benchmark data for %s from BenchmarkManager",
              benchmark_id)
          return existing_benchmark
      except Exception as e:
        self.logger.debug(
            "Failed to retrieve benchmark %s from BenchmarkManager: %s",
            benchmark_id, e)

    # Fallback to minimal benchmark creation
    self.logger.debug("Creating minimal benchmark for %s", benchmark_id)
    return Benchmark(
        project='unknown',
        language='unknown',
        function_signature='unknown',
        function_name='unknown',
        return_type='unknown',
        target_path='unknown',
        id=benchmark_id,
    )

  def _get_benchmark_metrics(self, benchmark_id: str) -> Dict[str, Any]:
    """Get comprehensive metrics for a specific benchmark."""
    try:
      # Get latest resul
      result = self.get_result(benchmark_id)
      if not result:
        return self._get_empty_metrics()

      # Calculate core metrics
      metrics = {
          # Core Metrics
          'compiles':
              result.is_build_successful(),
          'crashes':
              not result.is_run_successful() if result.run_info else False,
          'coverage':
              self._get_coverage_value(result),
          'line_coverage_diff':
              self._get_line_coverage_diff(result),

          # Derived Metrics
          'has_semantic_error':
              result.is_semantic_error(),
          'build_success_rate':
              self.get_build_success_rate(benchmark_id),
          'crash_rate':
              self._calculate_crash_rate(benchmark_id),

          # Coverage Metrics
          'cov_pcs':
              self._get_cov_pcs(result),
          'total_pcs':
              self._get_total_pcs(result),
          'coverage_percentage':
              self._get_coverage_percentage(result),

          # Quality Metrics
          'is_true_bug':
              self._is_true_bug(result),
          'error_type':
              self._get_error_type(result),

          # Metadata
          'trial':
              result.trial,
          'iteration':
              result.iteration,
          'timestamp':
              datetime.now().isoformat(),
          'benchmark_id':
              benchmark_id,
      }

      return metrics

    except Exception as e:
      self.logger.error("Failed to calculate benchmark metrics for %s: %s",
                        benchmark_id, str(e))
      return self._get_empty_metrics()

  def _get_aggregated_metrics(self) -> Dict[str, Any]:
    """Get aggregated metrics across all benchmarks."""
    try:
      # Get build statistics
      build_stats = self.build_mgr.get_build_statistics()
      total_builds = build_stats.get('total_builds', 0)
      successful_builds = build_stats.get('successful_builds', 0)

      # Get crash statistics
      crash_stats = self.crash_mgr.get_crash_statistics()
      total_crashes = crash_stats.get('total_crashes', 0)
      unique_crashes = crash_stats.get('unique_crashes', 0)

      # Get coverage statistics from recent coverage history
      coverage_history = self.coverage_mgr.get_coverage_history(limit=100)
      coverage_values = [
          entry.get('line_coverage', 0.0)
          for entry in coverage_history
          if entry.get('line_coverage') is not None
      ]

      average_coverage = sum(coverage_values) / len(
          coverage_values) if coverage_values else 0.0
      max_coverage = max(coverage_values) if coverage_values else 0.0

      # Estimate total benchmarks from unique benchmark IDs in build history
      build_history = self.build_mgr.get_build_history(limit=1000)
      unique_benchmarks = set(
          entry.get('benchmark_id')
          for entry in build_history
          if entry.get('benchmark_id'))
      total_benchmarks = len(unique_benchmarks)

      return {
          'total_benchmarks':
              total_benchmarks,
          'total_builds':
              total_builds,
          'successful_builds':
              successful_builds,
          'build_success_rate':
              successful_builds / total_builds if total_builds > 0 else 0.0,
          'total_crashes':
              total_crashes,
          'unique_crashes':
              unique_crashes,
          'crash_rate':
              total_crashes / total_builds if total_builds > 0 else 0.0,
          'average_coverage':
              average_coverage,
          'max_coverage':
              max_coverage,
          'coverage_samples':
              len(coverage_values),
          'timestamp':
              datetime.now().isoformat(),
      }

    except Exception as e:
      self.logger.error("Failed to calculate aggregated metrics: %s", str(e))
      # Return empty metrics on error
      return {
          'total_benchmarks': 0,
          'total_builds': 0,
          'successful_builds': 0,
          'build_success_rate': 0.0,
          'total_crashes': 0,
          'unique_crashes': 0,
          'crash_rate': 0.0,
          'average_coverage': 0.0,
          'max_coverage': 0.0,
          'coverage_samples': 0,
          'timestamp': datetime.now().isoformat(),
          'error': str(e),
      }

  def _get_empty_metrics(self) -> Dict[str, Any]:
    """Return empty metrics structure."""
    return {
        'compiles': False,
        'crashes': False,
        'coverage': 0.0,
        'line_coverage_diff': 0.0,
        'has_semantic_error': False,
        'build_success_rate': 0.0,
        'crash_rate': 0.0,
        'cov_pcs': 0,
        'total_pcs': 0,
        'coverage_percentage': 0.0,
        'is_true_bug': False,
        'error_type': 'UNKNOWN',
        'trial': 0,
        'iteration': 0,
        'timestamp': datetime.now().isoformat(),
        'benchmark_id': '',
    }

  def _get_coverage_value(self, result: Result) -> float:
    """Extract coverage value from Result."""
    if (result.analysis_info and result.analysis_info.coverage_analysis):
      return result.analysis_info.coverage_analysis.line_coverage
    return 0.0

  def _get_line_coverage_diff(self, result: Result) -> float:
    """Extract line coverage diff from Result."""
    if (result.analysis_info and result.analysis_info.coverage_analysis):
      return result.analysis_info.coverage_analysis.line_coverage_diff
    return 0.0

  def _get_cov_pcs(self, result: Result) -> int:
    """Extract covered program counters from Result."""
    if result.run_info:
      return result.run_info.cov_pcs
    if (result.analysis_info and result.analysis_info.coverage_analysis):
      return result.analysis_info.coverage_analysis.cov_pcs
    return 0

  def _get_total_pcs(self, result: Result) -> int:
    """Extract total program counters from Result."""
    if result.run_info:
      return result.run_info.total_pcs
    if (result.analysis_info and result.analysis_info.coverage_analysis):
      return result.analysis_info.coverage_analysis.total_pcs
    return 0

  def _get_coverage_percentage(self, result: Result) -> float:
    """Calculate coverage percentage from Result."""
    cov_pcs = self._get_cov_pcs(result)
    total_pcs = self._get_total_pcs(result)
    if total_pcs > 0:
      return (cov_pcs / total_pcs) * 100.0
    return 0.0

  def _is_true_bug(self, result: Result) -> bool:
    """Determine if Result represents a true bug."""
    if (result.analysis_info and result.analysis_info.crash_analysis):
      return result.analysis_info.crash_analysis.true_bug
    return False

  def _get_error_type(self, result: Result) -> str:
    """Extract error type from Result."""
    if (result.analysis_info and result.analysis_info.coverage_analysis and
        result.analysis_info.coverage_analysis.error_type):
      return result.analysis_info.coverage_analysis.error_type.name
    return 'UNKNOWN'

  def _calculate_crash_rate(self, benchmark_id: str) -> float:
    """Calculate crash rate for a benchmark."""
    try:
      # Get crash statistics for the last 30 days
      crash_summary = self.get_crash_summary(benchmark_id, days=30)
      total_crashes = crash_summary.get('total_crashes', 0)

      # Get build statistics to determine total runs
      # Try with date parameters first, fallback to no parameters
      try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        build_stats = self.build_mgr.get_build_statistics(
            start_date.isoformat(), end_date.isoformat())
      except (TypeError, AttributeError):
        # Fallback if get_build_statistics doesn't accept date parameters
        build_stats = self.build_mgr.get_build_statistics()

      total_builds = build_stats.get('total_builds', 0)

      if total_builds > 0:
        return total_crashes / total_builds
      return 0.0

    except Exception as e:
      self.logger.error("Failed to calculate crash rate for %s: %s",
                        benchmark_id, str(e))
      return 0.0
