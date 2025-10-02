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
"""
Simple unit tests for ResultManager using mock HistoryManagers.

This module tests the core functionality of ResultManager without requiring
external dependencies like pydantic, yaml, etc.
"""

import unittest
from datetime import datetime

from ossfuzz_py.core.benchmark_manager import Benchmark
from ossfuzz_py.result.result_manager import ResultManager
from ossfuzz_py.result.results import (AnalysisInfo, BuildInfo,
                                       CoverageAnalysis, Result, RunInfo)


class TestResultManagerSimple(unittest.TestCase):
  """Test ResultManager with mock HistoryManager classes."""

  def setUp(self):
    """Set up test environment with mock HistoryManagers."""
    # Create mock HistoryManager instances with proper mock behavior
    from unittest.mock import Mock
    self.build_mgr = Mock()
    self.crash_mgr = Mock()
    self.corpus_mgr = Mock()
    self.coverage_mgr = Mock()

    # Configure mock methods to return appropriate empty data
    self.build_mgr.get_build_history.return_value = []
    self.build_mgr.get_build_statistics.return_value = {
        'total_builds': 0,
        'successful_builds': 0
    }
    self.build_mgr.store_build_result.return_value = True

    self.crash_mgr.get_crash_history.return_value = []
    self.crash_mgr.get_crash_statistics.return_value = {'total_crashes': 0}
    self.crash_mgr.store_crash.return_value = True
    self.crash_mgr.check_duplicate_crash.return_value = False

    self.corpus_mgr.get_corpus_history.return_value = []
    self.corpus_mgr.store_corpus.return_value = True

    self.coverage_mgr.get_coverage_history.return_value = []
    self.coverage_mgr.store_coverage.return_value = True

    # Create ResultManager
    self.result_manager = ResultManager(
        build_mgr=self.build_mgr,
        crash_mgr=self.crash_mgr,
        corpus_mgr=self.corpus_mgr,
        coverage_mgr=self.coverage_mgr,
    )

  def test_result_manager_creation(self):
    """Test that ResultManager can be created successfully."""
    self.assertIsNotNone(self.result_manager)
    self.assertEqual(self.result_manager.build_mgr, self.build_mgr)
    self.assertEqual(self.result_manager.crash_mgr, self.crash_mgr)
    self.assertEqual(self.result_manager.corpus_mgr, self.corpus_mgr)
    self.assertEqual(self.result_manager.coverage_mgr, self.coverage_mgr)

  def test_store_and_retrieve_build_result(self):
    """Test storing and retrieving a build result."""
    # Create test benchmark
    benchmark = Benchmark(
        project='test_project',
        language='c++',
        function_signature='int test_function(const char* input)',
        function_name='test_function',
        return_type='int',
        target_path='/path/to/test.h',
        id='test_benchmark_build',
    )

    # Create build result
    build_info = BuildInfo(
        compiles=True,
        compile_log='Build successful',
        errors=[],
        binary_exists=True,
        is_function_referenced=True,
        fuzz_target_source='// Test fuzz target source',
        build_script_source='// Test build script',
    )

    result = Result(
        benchmark=benchmark,
        work_dirs='/tmp/work',
        trial=1,
        build_info=build_info,
    )

    # Store the result
    benchmark_id = 'test_benchmark_build'
    try:
      self.result_manager.store_result(benchmark_id, result)
    except Exception as e:
      self.fail(f"store_result should not raise exception: {e}")

  def test_get_metrics_with_no_data(self):
    """Test getting metrics when no data is available."""
    metrics = self.result_manager.get_metrics('nonexistent_benchmark')

    # Should return empty metrics structure
    self.assertIsInstance(metrics, dict)
    self.assertIn('compiles', metrics)
    self.assertIn('crashes', metrics)
    self.assertIn('coverage', metrics)
    self.assertIn('benchmark_id', metrics)

  def test_get_aggregated_metrics(self):
    """Test getting aggregated metrics across all benchmarks."""
    metrics = self.result_manager.get_metrics()

    # Should return aggregated metrics structure
    self.assertIsInstance(metrics, dict)
    self.assertIn('total_benchmarks', metrics)
    self.assertIn('total_builds', metrics)
    self.assertIn('build_success_rate', metrics)
    self.assertIn('timestamp', metrics)

  def test_get_trial_result_nonexistent(self):
    """Test getting trial result for non-existent trial."""
    result = self.result_manager.get_trial_result('nonexistent_benchmark', 1)
    self.assertIsNone(result)

  def test_coverage_trend(self):
    """Test coverage trend functionality."""
    start_date = datetime.now()
    end_date = datetime.now()

    trend_data = self.result_manager.coverage_trend('test_benchmark',
                                                    start_date, end_date)

    # Should return empty DataFrame (since no data)
    # Check if it's a pandas DataFrame or a list
    if hasattr(trend_data, 'empty'):
      # It's a DataFrame
      self.assertTrue(trend_data.empty)  # type: ignore
    else:
      # It's a list
      self.assertIsInstance(trend_data, list)
      self.assertEqual(len(trend_data), 0)

  def test_latest_successful_build(self):
    """Test getting latest successful build."""
    result = self.result_manager.latest_successful_build('test_benchmark')
    # Should return None since no data
    self.assertIsNone(result)

  def test_get_build_success_rate(self):
    """Test getting build success rate."""
    rate = self.result_manager.get_build_success_rate('test_benchmark')
    # Should return 0.0 since no data
    self.assertIsInstance(rate, float)
    self.assertEqual(rate, 0.0)

  def test_get_crash_summary(self):
    """Test getting crash summary."""
    summary = self.result_manager.get_crash_summary('test_benchmark')
    # Should return empty dict since no data
    self.assertIsInstance(summary, dict)

  def test_store_result_with_run_info(self):
    """Test storing result with run info."""
    benchmark = Benchmark(
        project='test_project',
        language='c++',
        function_signature='int test_function(const char* input)',
        function_name='test_function',
        return_type='int',
        target_path='/path/to/test.h',
        id='test_benchmark_run',
    )

    run_info = RunInfo(
        crashes=True,
        run_log='Fuzzer run log',
        corpus_path='/tmp/corpus',
        cov_pcs=100,
        total_pcs=1000,
        crash_info='Test crash info',
    )

    result = Result(
        benchmark=benchmark,
        work_dirs='/tmp/work',
        trial=1,
        run_info=run_info,
    )

    # Store the result
    benchmark_id = 'test_benchmark_run'
    try:
      self.result_manager.store_result(benchmark_id, result)
    except Exception as e:
      self.fail(f"store_result with run_info should not raise exception: {e}")

  def test_store_result_with_analysis_info(self):
    """Test storing result with analysis info."""
    benchmark = Benchmark(
        project='test_project',
        language='c++',
        function_signature='int test_function(const char* input)',
        function_name='test_function',
        return_type='int',
        target_path='/path/to/test.h',
        id='test_benchmark_analysis',
    )

    coverage_analysis = CoverageAnalysis(
        line_coverage=75.5,
        line_coverage_diff=15.2,
        coverage_report_path='/tmp/coverage_report',
        textcov_diff=None,
        cov_pcs=100,
        total_pcs=1000,
    )

    analysis_info = AnalysisInfo(coverage_analysis=coverage_analysis)

    result = Result(
        benchmark=benchmark,
        work_dirs='/tmp/work',
        trial=1,
        analysis_info=analysis_info,
    )

    # Store the result
    benchmark_id = 'test_benchmark_analysis'
    try:
      self.result_manager.store_result(benchmark_id, result)
    except Exception as e:
      self.fail(
          f"store_result with analysis_info should not raise exception: {e}")

  def test_error_handling(self):
    """Test error handling for invalid inputs."""
    # Test with invalid benchmark_id and result
    try:
      # Use type: ignore to suppress type checker warnings for intentional test
      self.result_manager.store_result(None, None)  # type: ignore
    except Exception:
      pass  # Expected to fail

    # Test with invalid trial_id - should return None gracefully
    result = self.result_manager.get_trial_result('test', -1)
    # Should handle gracefully and return None
    self.assertIsNone(result)

  def test_helper_methods(self):
    """Test helper methods work correctly."""
    # Test _create_minimal_benchmark
    benchmark = self.result_manager._create_minimal_benchmark('test_id')  # pylint: disable=protected-access
    self.assertIsInstance(benchmark, Benchmark)
    # The ID is auto-generated, so just check it's not empty
    self.assertIsNotNone(benchmark.id)
    self.assertTrue(len(benchmark.id) > 0)

    # Test _get_empty_metrics
    empty_metrics = self.result_manager._get_empty_metrics()  # pylint: disable=protected-access
    self.assertIsInstance(empty_metrics, dict)
    self.assertIn('compiles', empty_metrics)
    self.assertIn('crashes', empty_metrics)


if __name__ == '__main__':
  unittest.main()
