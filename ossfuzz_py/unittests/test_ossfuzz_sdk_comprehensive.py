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
Comprehensive unit tests for the enhanced OSS-Fuzz SDK facade.

This module tests all functionality of the comprehensive SDK facade including
build operations, execution operations, result management, benchmark management,
workflow orchestration, and historical data analysis.
"""

import tempfile
import unittest
from pathlib import Path

from ossfuzz_py.core.ossfuzz_sdk import (BuildOptions, BuildResult, OSSFuzzSDK,
                                         PipelineOptions, PipelineResult,
                                         RunOptions, RunResult, SDKConfig)


class TestOSSFuzzSDKComprehensive(unittest.TestCase):
  """Comprehensive test suite for the enhanced OSS-Fuzz SDK facade."""

  def setUp(self):
    """Set up test environment."""
    self.temp_dir = tempfile.mkdtemp()
    self.config = SDKConfig(storage_backend='local',
                            storage_path=self.temp_dir,
                            work_dir=self.temp_dir,
                            log_level='INFO')
    self.sdk = OSSFuzzSDK('test_project', self.config)

  def tearDown(self):
    """Clean up test environment."""
    import shutil
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  # Configuration Tests

  def test_sdk_config_creation(self):
    """Test SDKConfig creation and conversion."""
    config = SDKConfig(storage_backend='gcs',
                       gcs_bucket_name='test-bucket',
                       enable_caching=False)

    config_dict = config.to_dict()
    self.assertEqual(config_dict['storage_backend'], 'gcs')
    self.assertEqual(config_dict['gcs_bucket_name'], 'test-bucket')
    self.assertFalse(config_dict['enable_caching'])

  def test_sdk_initialization_with_config_object(self):
    """Test SDK initialization with SDKConfig object."""
    config = SDKConfig(storage_backend='local', log_level='DEBUG')
    sdk = OSSFuzzSDK('test_project', config)

    self.assertEqual(sdk.project_name, 'test_project')
    self.assertEqual(sdk.sdk_config.storage_backend, 'local')
    self.assertEqual(sdk.sdk_config.log_level, 'DEBUG')

  def test_sdk_initialization_with_dict_config(self):
    """Test SDK initialization with dictionary config."""
    config_dict = {'storage_backend': 'local', 'log_level': 'WARNING'}
    sdk = OSSFuzzSDK('test_project', config_dict)

    self.assertEqual(sdk.project_name, 'test_project')
    self.assertEqual(sdk.sdk_config.storage_backend, 'local')
    self.assertEqual(sdk.sdk_config.log_level, 'WARNING')

  def test_options_classes(self):
    """Test options classes creation and properties."""
    # Test BuildOptions
    build_opts = BuildOptions(sanitizer='memory',
                              architecture='arm64',
                              timeout_seconds=1800)
    self.assertEqual(build_opts.sanitizer, 'memory')
    self.assertEqual(build_opts.architecture, 'arm64')
    self.assertEqual(build_opts.timeout_seconds, 1800)

    # Test RunOptions
    run_opts = RunOptions(duration_seconds=600,
                          detect_leaks=False,
                          extract_coverage=True)
    self.assertEqual(run_opts.duration_seconds, 600)
    self.assertFalse(run_opts.detect_leaks)
    self.assertTrue(run_opts.extract_coverage)

    # Test PipelineOptions
    pipeline_opts = PipelineOptions(build_options=build_opts,
                                    run_options=run_opts,
                                    trials=3)
    self.assertEqual(pipeline_opts.trials, 3)
    self.assertEqual(pipeline_opts.build_options.sanitizer, 'memory')
    self.assertEqual(pipeline_opts.run_options.duration_seconds, 600)

  # Build Operations Tests

  def test_build_fuzz_target_no_builder(self):
    """Test build_fuzz_target when builder not available."""
    # SDK should not have builder available in test environment
    target_spec = {
        'name': 'test_target',
        'source_code': '// Test source',
        'build_script': '// Test build script',
        'project_name': 'test_project',
        'language': 'c++'
    }

    result = self.sdk.build_fuzz_target(target_spec)

    self.assertIsInstance(result, BuildResult)
    self.assertFalse(result.success)
    # Build components are available, but build fails due to missing directory
    self.assertIn('Build failed', result.message)

  def test_build_benchmark_no_manager(self):
    """Test build_benchmark when benchmark not found."""
    result = self.sdk.build_benchmark('test_benchmark')

    self.assertIsInstance(result, BuildResult)
    self.assertFalse(result.success)
    self.assertIn('Benchmark not found', result.message)

  def test_get_build_status(self):
    """Test get_build_status method."""
    status = self.sdk.get_build_status('test_build_id')

    self.assertIsInstance(status, dict)
    self.assertEqual(status['build_id'], 'test_build_id')
    self.assertIn('status', status)
    self.assertIn('timestamp', status)

  def test_get_build_artifacts(self):
    """Test get_build_artifacts method."""
    artifacts = self.sdk.get_build_artifacts('test_build_id')

    self.assertIsInstance(artifacts, dict)
    self.assertEqual(artifacts['build_id'], 'test_build_id')
    self.assertIn('artifacts', artifacts)

  def test_list_recent_builds(self):
    """Test list_recent_builds method."""
    builds = self.sdk.list_recent_builds(limit=5)

    self.assertIsInstance(builds, list)
    # Should be empty since no build history available

  def test_list_recent_builds_with_filters(self):
    """Test list_recent_builds with filters."""
    filters = {'status': 'success'}
    builds = self.sdk.list_recent_builds(limit=10, filters=filters)

    self.assertIsInstance(builds, list)

  # Execution Operations Tests

  def test_run_fuzz_target_no_runner(self):
    """Test run_fuzz_target when runner not available."""
    target_spec = {
        'name': 'test_target',
        'source_code': '// Test source',
        'project_name': 'test_project',
        'language': 'c++'
    }
    build_metadata = {'artifacts': {}}

    result = self.sdk.run_fuzz_target(target_spec, build_metadata)

    self.assertIsInstance(result, RunResult)
    self.assertFalse(result.success)
    # Check for actual error message about missing build_script
    self.assertIn('Failed to run fuzz target', result.message)

  def test_run_benchmark_no_manager(self):
    """Test run_benchmark when benchmark manager not available."""
    result = self.sdk.run_benchmark('test_benchmark')

    self.assertIsInstance(result, RunResult)
    self.assertFalse(result.success)
    # Should fail at build stage first

  def test_get_run_status(self):
    """Test get_run_status method."""
    status = self.sdk.get_run_status('test_run_id')

    self.assertIsInstance(status, dict)
    self.assertEqual(status['run_id'], 'test_run_id')
    self.assertIn('status', status)
    self.assertIn('timestamp', status)

  def test_get_run_results(self):
    """Test get_run_results method."""
    results = self.sdk.get_run_results('test_run_id')

    self.assertIsInstance(results, dict)
    self.assertEqual(results['run_id'], 'test_run_id')
    self.assertIn('results', results)

  def test_list_recent_runs(self):
    """Test list_recent_runs method."""
    runs = self.sdk.list_recent_runs(limit=5)

    self.assertIsInstance(runs, list)
    # Should be empty since no run history available

  # Workflow Orchestration Tests

  def test_run_full_pipeline_no_components(self):
    """Test run_full_pipeline when components not available."""
    options = PipelineOptions(trials=2)
    result = self.sdk.run_full_pipeline('test_benchmark', options)

    self.assertIsInstance(result, PipelineResult)
    self.assertFalse(result.success)
    self.assertEqual(len(result.build_results), 2)  # Should attempt all trials
    # All builds should fail due to missing components

  def test_pipeline_options_defaults(self):
    """Test PipelineOptions with default values."""
    options = PipelineOptions()

    self.assertEqual(options.trials, 1)
    self.assertTrue(options.analyze_coverage)
    self.assertTrue(options.store_results)
    self.assertIsInstance(options.build_options, BuildOptions)
    self.assertIsInstance(options.run_options, RunOptions)

  # Result Management Tests

  def test_get_benchmark_result_no_manager(self):
    """Test get_benchmark_result when ResultManager not available."""
    result = self.sdk.get_benchmark_result('test_benchmark')

    self.assertIsNone(result)

  def test_get_benchmark_result_with_trial(self):
    """Test get_benchmark_result with specific trial."""
    result = self.sdk.get_benchmark_result('test_benchmark', trial=1)

    self.assertIsNone(result)  # No ResultManager available

  def test_get_benchmark_metrics_no_manager(self):
    """Test get_benchmark_metrics when ResultManager not available."""
    metrics = self.sdk.get_benchmark_metrics('test_benchmark')

    self.assertIsInstance(metrics, dict)
    # Should return empty metrics structure (not empty dict)
    self.assertIn('compiles', metrics)
    self.assertIn('crashes', metrics)
    self.assertIn('coverage', metrics)

  def test_get_system_metrics_no_manager(self):
    """Test get_system_metrics when ResultManager not available."""
    metrics = self.sdk.get_system_metrics()

    self.assertIsInstance(metrics, dict)
    # Should return aggregated metrics structure (not empty dict)
    self.assertIn('total_benchmarks', metrics)
    self.assertIn('total_builds', metrics)
    self.assertIn('build_success_rate', metrics)

  def test_get_coverage_trend_no_manager(self):
    """Test get_coverage_trend when ResultManager not available."""
    trend = self.sdk.get_coverage_trend('test_benchmark', days=7)

    # Can be either list or DataFrame depending on pandas availability
    if hasattr(trend, 'empty'):
      # It's a DataFrame
      self.assertTrue(trend.empty)  # type: ignore
    else:
      # It's a list
      self.assertIsInstance(trend, list)
      self.assertEqual(len(trend), 0)

  def test_get_build_success_rate_no_manager(self):
    """Test get_build_success_rate when ResultManager not available."""
    rate = self.sdk.get_build_success_rate('test_benchmark', days=7)

    self.assertIsInstance(rate, float)
    self.assertEqual(rate, 0.0)

  def test_get_crash_summary_no_manager(self):
    """Test get_crash_summary when ResultManager not available."""
    summary = self.sdk.get_crash_summary('test_benchmark', days=7)

    self.assertIsInstance(summary, dict)
    # Should return crash summary structure (may have default values)
    # Just check it's a dict, don't assume it's empty

  # Historical Data Tests (preserved functionality)

  def test_generate_project_report(self):
    """Test generate_project_report method."""
    report = self.sdk.generate_project_report(days=7)

    self.assertIsInstance(report, dict)
    self.assertIn('project_name', report)
    self.assertEqual(report['project_name'], 'test_project')

  def test_get_project_summary(self):
    """Test get_project_summary method."""
    summary = self.sdk.get_project_summary()

    self.assertIsInstance(summary, dict)
    self.assertIn('project_name', summary)

  def test_analyze_fuzzing_efficiency(self):
    """Test analyze_fuzzing_efficiency method."""
    efficiency = self.sdk.analyze_fuzzing_efficiency(days=7)

    self.assertIsInstance(efficiency, dict)
    self.assertIn('overall_efficiency', efficiency)

  # Error Handling Tests

  def test_invalid_project_name(self):
    """Test SDK initialization with invalid project name."""
    with self.assertRaises(Exception):
      OSSFuzzSDK('', self.config)

  def test_error_handling_in_methods(self):
    """Test error handling in various methods."""
    # All methods should handle errors gracefully and not raise exceptions

    # Build operations
    self.assertIsInstance(self.sdk.get_build_status('invalid'), dict)
    self.assertIsInstance(self.sdk.get_build_artifacts('invalid'), dict)
    self.assertIsInstance(self.sdk.list_recent_builds(), list)

    # Run operations
    self.assertIsInstance(self.sdk.get_run_status('invalid'), dict)
    self.assertIsInstance(self.sdk.get_run_results('invalid'), dict)
    self.assertIsInstance(self.sdk.list_recent_runs(), list)

    # Result operations
    self.assertIsNone(self.sdk.get_benchmark_result('invalid'))
    self.assertIsInstance(self.sdk.get_benchmark_metrics('invalid'), dict)
    self.assertIsInstance(self.sdk.get_system_metrics(), dict)

  # Component Integration Tests

  def test_component_availability_checking(self):
    """Test component availability checking."""
    # In test environment, most components should not be available
    self.assertIsNotNone(self.sdk.storage)
    # Other components may or may not be available depending on dependencies

  def test_environment_config_loading(self):
    """Test environment configuration loading."""
    # Should not raise exceptions
    self.sdk._load_config_from_env()  # pylint: disable=protected-access

    # Config should still be valid
    self.assertIsInstance(self.sdk.config, dict)

  def test_component_initialization(self):
    """Test component initialization."""
    # Should not raise exceptions
    self.sdk._initialize_components()  # pylint: disable=protected-access

    # SDK should still be functional
    self.assertEqual(self.sdk.project_name, 'test_project')

  # Result Classes Tests

  def test_build_result_creation(self):
    """Test BuildResult creation and properties."""
    result = BuildResult(success=True,
                         message='Build successful',
                         artifacts={'binary': '/path/to/binary'})

    self.assertTrue(result.success)
    self.assertEqual(result.message, 'Build successful')
    self.assertIn('binary', result.artifacts)
    self.assertIsNotNone(result.build_id)
    self.assertIsNotNone(result.timestamp)

  def test_run_result_creation(self):
    """Test RunResult creation and properties."""
    result = RunResult(success=True,
                       message='Run completed',
                       crashes=False,
                       coverage_data={
                           'cov_pcs': 100,
                           'total_pcs': 1000
                       })

    self.assertTrue(result.success)
    self.assertEqual(result.message, 'Run completed')
    self.assertFalse(result.crashes)
    self.assertEqual(result.coverage_data['cov_pcs'], 100)
    self.assertIsNotNone(result.run_id)
    self.assertIsNotNone(result.timestamp)

  def test_pipeline_result_creation(self):
    """Test PipelineResult creation and properties."""
    build_result = BuildResult(success=True, message='Build OK')
    run_result = RunResult(success=True, message='Run OK')

    pipeline_result = PipelineResult(success=True,
                                     message='Pipeline completed',
                                     build_results=[build_result],
                                     run_results=[run_result])

    self.assertTrue(pipeline_result.success)
    self.assertEqual(pipeline_result.message, 'Pipeline completed')
    self.assertEqual(len(pipeline_result.build_results), 1)
    self.assertEqual(len(pipeline_result.run_results), 1)
    self.assertIsNotNone(pipeline_result.pipeline_id)
    self.assertIsNotNone(pipeline_result.timestamp)

  # Export and Analysis Tests

  def test_export_results(self):
    """Test export_results method."""
    benchmark_ids = ['bench1', 'bench2', 'bench3']

    # Should handle missing ResultManager gracefully
    try:
      output_path = self.sdk.export_results(benchmark_ids, export_format='json')

      # Should create a file
      self.assertTrue(Path(output_path).exists())

      # Clean up
      Path(output_path).unlink(missing_ok=True)

    except Exception as e:
      # Should raise OSSFuzzSDKError for missing ResultManager
      self.assertIn('ResultManager not available', str(e))

  def test_export_results_with_custom_path(self):
    """Test export_results with custom output path."""
    benchmark_ids = ['bench1']
    custom_path = Path(self.temp_dir) / 'custom_export.json'

    try:
      output_path = self.sdk.export_results(benchmark_ids,
                                            export_format='json',
                                            output_path=str(custom_path))

      self.assertEqual(output_path, str(custom_path))

    except Exception as e:
      # Should raise OSSFuzzSDKError for missing ResultManager
      self.assertIn('ResultManager not available', str(e))

  def test_generate_comparison_report(self):
    """Test generate_comparison_report method."""
    benchmark_ids = ['bench1', 'bench2']

    report = self.sdk.generate_comparison_report(benchmark_ids, days=7)

    self.assertIsInstance(report, dict)
    self.assertIn('comparison_timestamp', report)
    self.assertIn('benchmark_count', report)
    self.assertEqual(report['benchmark_count'], 2)
    self.assertIn('benchmarks', report)

  # Benchmark Management Tests

  def test_create_benchmark(self):
    """Test create_benchmark method."""
    benchmark_spec = {
        'id': 'new_benchmark',
        'project': 'test_project',
        'function_name': 'test_function'
    }

    result = self.sdk.create_benchmark(benchmark_spec)

    # Should return True since BenchmarkManager is available
    self.assertTrue(result)

  def test_update_benchmark(self):
    """Test update_benchmark method."""
    updates = {'description': 'Updated description'}

    result = self.sdk.update_benchmark('test_benchmark', updates)

    # Should return True since BenchmarkManager is available
    self.assertTrue(result)

  def test_delete_benchmark(self):
    """Test delete_benchmark method."""
    result = self.sdk.delete_benchmark('test_benchmark')

    # Should return True since BenchmarkManager is available
    self.assertTrue(result)

  def test_list_benchmarks(self):
    """Test list_benchmarks method."""
    benchmarks = self.sdk.list_benchmarks()

    self.assertIsInstance(benchmarks, list)
    self.assertEqual(len(benchmarks), 0)  # No BenchmarkManager available

  def test_list_benchmarks_with_filters(self):
    """Test list_benchmarks with filters."""
    filters = {'language': 'c++'}
    benchmarks = self.sdk.list_benchmarks(filters=filters)

    self.assertIsInstance(benchmarks, list)
    self.assertEqual(len(benchmarks), 0)  # No BenchmarkManager available

  def test_search_benchmarks(self):
    """Test search_benchmarks method."""
    results = self.sdk.search_benchmarks('test', limit=5)

    self.assertIsInstance(results, list)
    self.assertEqual(len(results), 0)  # No BenchmarkManager available

  # Integration Tests

  def test_full_workflow_simulation(self):
    """Test a complete workflow simulation."""
    # This tests the full API without requiring actual components

    # 1. Create options
    build_opts = BuildOptions(sanitizer='address')
    run_opts = RunOptions(duration_seconds=300)
    pipeline_opts = PipelineOptions(build_options=build_opts,
                                    run_options=run_opts,
                                    trials=1)

    # 2. Run pipeline (should fail gracefully)
    result = self.sdk.run_full_pipeline('test_benchmark', pipeline_opts)
    self.assertIsInstance(result, PipelineResult)
    self.assertFalse(result.success)  # Expected to fail without components

    # 3. Check status
    build_status = self.sdk.get_build_status('test_build')
    self.assertIsInstance(build_status, dict)

    run_status = self.sdk.get_run_status('test_run')
    self.assertIsInstance(run_status, dict)

    # 4. Get metrics
    metrics = self.sdk.get_benchmark_metrics('test_benchmark')
    self.assertIsInstance(metrics, dict)

    # 5. Generate report
    report = self.sdk.generate_project_report(days=1)
    self.assertIsInstance(report, dict)

  def test_api_consistency(self):
    """Test API consistency and method availability."""
    # Check that all expected methods exist
    expected_methods = [
        # Build operations
        'build_fuzz_target',
        'build_benchmark',
        'get_build_status',
        'get_build_artifacts',
        'list_recent_builds',

        # Execution operations
        'run_fuzz_target',
        'run_benchmark',
        'get_run_status',
        'get_run_results',
        'list_recent_runs',

        # Workflow orchestration
        'run_full_pipeline',

        # Result management
        'get_benchmark_result',
        'get_benchmark_metrics',
        'get_system_metrics',
        'get_coverage_trend',
        'get_build_success_rate',
        'get_crash_summary',

        # Benchmark management
        'create_benchmark',
        'update_benchmark',
        'delete_benchmark',
        'list_benchmarks',
        'search_benchmarks',

        # Export and analysis
        'export_results',
        'generate_comparison_report',

        # Historical data (preserved)
        'generate_project_report',
        'get_project_summary',
        'analyze_fuzzing_efficiency'
    ]

    for method_name in expected_methods:
      self.assertTrue(hasattr(self.sdk, method_name),
                      f"Method {method_name} not found")
      self.assertTrue(callable(getattr(self.sdk, method_name)),
                      f"Method {method_name} not callable")

  def test_method_signatures(self):
    """Test method signatures for consistency."""
    import inspect

    # Test key method signatures
    build_target_sig = inspect.signature(self.sdk.build_fuzz_target)
    self.assertIn('target_spec', build_target_sig.parameters)
    self.assertIn('options', build_target_sig.parameters)

    run_pipeline_sig = inspect.signature(self.sdk.run_full_pipeline)
    self.assertIn('benchmark_id', run_pipeline_sig.parameters)
    self.assertIn('options', run_pipeline_sig.parameters)

    export_sig = inspect.signature(self.sdk.export_results)
    self.assertIn('benchmark_ids', export_sig.parameters)
    self.assertIn('export_format', export_sig.parameters)


if __name__ == '__main__':
  unittest.main()
