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
Unit tests for the Historical Data SDK.

This module contains tests for the main SDK components including
the OSSFuzzSDK facade and history managers.
"""

import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from ossfuzz_py.core.ossfuzz_sdk import OSSFuzzSDK
from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.errors import OSSFuzzSDKConfigError
from ossfuzz_py.history import (BuildHistoryManager, CorpusHistoryManager,
                                CoverageHistoryManager, CrashHistoryManager)


class TestOSSFuzzSDK(unittest.TestCase):
  """Test cases for the OSSFuzzSDK class."""

  def setUp(self):
    """Set up test fixtures."""
    self.temp_dir = tempfile.mkdtemp()
    self.config = {'storage_backend': 'local', 'storage_path': self.temp_dir}
    self.project_name = 'test_project'

  def tearDown(self):
    """Clean up test fixtures."""
    import shutil
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_sdk_initialization(self):
    """Test SDK initialization with valid configuration."""
    sdk = OSSFuzzSDK(self.project_name, self.config)

    self.assertEqual(sdk.project_name, self.project_name)
    self.assertIsInstance(sdk.storage, StorageManager)
    self.assertIsInstance(sdk.build, BuildHistoryManager)
    self.assertIsInstance(sdk.crash, CrashHistoryManager)
    self.assertIsInstance(sdk.corpus, CorpusHistoryManager)
    self.assertIsInstance(sdk.coverage, CoverageHistoryManager)

  def test_sdk_initialization_without_project_name(self):
    """Test SDK initialization fails without project name."""
    with self.assertRaises(OSSFuzzSDKConfigError):
      OSSFuzzSDK('', self.config)

  def test_sdk_initialization_without_config(self):
    """Test SDK initialization with default configuration."""
    sdk = OSSFuzzSDK(self.project_name)
    self.assertEqual(sdk.project_name, self.project_name)
    self.assertIsInstance(sdk.storage, StorageManager)

  @patch.dict(
      'os.environ', {
          'OSSFUZZ_HISTORY_STORAGE_BACKEND': 'local',
          'OSSFUZZ_HISTORY_STORAGE_PATH': '/tmp/test'
      })
  def test_config_from_environment(self):
    """Test configuration loading from environment variables."""
    sdk = OSSFuzzSDK(self.project_name)
    self.assertEqual(sdk.config.get('storage_backend'), 'local')
    self.assertEqual(sdk.config.get('storage_path'), '/tmp/test')

  def test_generate_project_report(self):
    """Test project report generation."""
    sdk = OSSFuzzSDK(self.project_name, self.config)

    # Mock the history managers to return test data
    with (patch.object(sdk.build, 'get_build_statistics') as mock_build_stats, \
         patch.object(sdk.build, 'get_build_trends') as mock_build_trends, \
         patch.object(sdk.crash, 'get_crash_statistics') as mock_crash_stats, \
         patch.object(sdk.coverage, 'get_coverage_report')
          as mock_coverage_report, \
         patch.object(sdk.coverage, 'analyze_coverage_trends') as
          mock_coverage_trends, \
         patch.object(sdk.corpus, 'get_corpus_growth') as mock_corpus_growth):

      # Set up mock return values
      mock_build_stats.return_value = {'success_rate': 85.0, 'total_builds': 10}
      mock_build_trends.return_value = {
          'trend': 'improving',
          'builds_per_day': 2.0
      }
      mock_crash_stats.return_value = {'total_crashes': 5, 'unique_crashes': 3}
      mock_coverage_report.return_value = {
          'summary': {
              'max_line_coverage': 75.0
          }
      }
      mock_coverage_trends.return_value = {
          'trend': 'improving',
          'coverage_velocity': 0.5
      }
      mock_corpus_growth.return_value = {
          'growth_rate': 10.0,
          'trend': 'growing'
      }

      report = sdk.generate_project_report(days=7)

      self.assertEqual(report['project_name'], self.project_name)
      self.assertIn('build_summary', report)
      self.assertIn('crash_summary', report)
      self.assertIn('coverage_summary', report)
      self.assertIn('corpus_summary', report)
      self.assertIn('health_score', report)

  def test_analyze_fuzzing_efficiency(self):
    """Test fuzzing efficiency analysis."""
    sdk = OSSFuzzSDK(self.project_name, self.config)

    # Mock the history managers to return test data
    with (patch.object(sdk.build, 'get_build_trends') as mock_build_trends, \
         patch.object(sdk.coverage, 'analyze_coverage_trends')
         as mock_coverage_trends, \
         patch.object(sdk.crash, 'get_crash_statistics') as mock_crash_stats, \
         patch.object(sdk.corpus, 'get_corpus_growth') as mock_corpus_growth):

      # Set up mock return values
      mock_build_trends.return_value = {
          'builds_per_day': 2.0,
          'average_success_rate': 85.0,
          'trend': 'improving'
      }
      mock_coverage_trends.return_value = {
          'coverage_velocity': 0.5,
          'stability': 'stable',
          'current_coverage': 75.0
      }
      mock_crash_stats.return_value = {'total_crashes': 10, 'unique_crashes': 8}
      mock_corpus_growth.return_value = {
          'growth_rate': 15.0,
          'size_change': 100,
          'trend': 'growing'
      }

      analysis = sdk.analyze_fuzzing_efficiency(days=7)

      self.assertEqual(analysis['project_name'], self.project_name)
      self.assertIn('build_efficiency', analysis)
      self.assertIn('coverage_efficiency', analysis)
      self.assertIn('crash_efficiency', analysis)
      self.assertIn('corpus_efficiency', analysis)
      self.assertIn('overall_efficiency', analysis)

  def test_get_project_summary(self):
    """Test project summary generation."""
    sdk = OSSFuzzSDK(self.project_name, self.config)

    # Mock the history managers to return test data
    with (patch.object(sdk.build, 'get_last_successful_build')
          as mock_last_build, \
         patch.object(sdk.coverage, 'get_latest_coverage')
         as mock_latest_coverage, \
         patch.object(sdk.crash, 'get_crash_history')
          as mock_crash_history):

      # Set up mock return values
      mock_last_build.return_value = {
          'build_id': 'build_123',
          'timestamp': '2025-01-01T12:00:00',
          'success': True
      }
      mock_latest_coverage.return_value = {
          'timestamp': '2025-01-01T12:00:00',
          'line_coverage': 75.0
      }
      mock_crash_history.return_value = [{
          'crash_id': 'crash_1',
          'timestamp': '2025-01-01T10:00:00'
      }, {
          'crash_id': 'crash_2',
          'timestamp': '2025-01-01T11:00:00'
      }]

      summary = sdk.get_project_summary()

      self.assertEqual(summary['project_name'], self.project_name)
      self.assertIn('last_successful_build', summary)
      self.assertIn('latest_coverage', summary)
      self.assertEqual(summary['recent_crashes'], 2)


class TestHistoryManagers(unittest.TestCase):
  """Test cases for history managers."""

  def setUp(self):
    """Set up test fixtures."""
    self.temp_dir = tempfile.mkdtemp()
    self.config = {'storage_backend': 'local', 'storage_path': self.temp_dir}
    self.project_name = 'test_project'
    self.storage_manager = StorageManager(self.config)

  def tearDown(self):
    """Clean up test fixtures."""
    import shutil
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_build_history_manager(self):
    """Test BuildHistoryManager functionality."""
    manager = BuildHistoryManager(self.storage_manager, self.project_name)

    # Test storing build result
    build_data = {
        'build_id': 'build_123',
        'timestamp': datetime.now().isoformat(),
        'project_name': self.project_name,
        'success': True,
        'duration_seconds': 300
    }

    result = manager.store_build_result(build_data)
    self.assertIsInstance(result, str)

    # Test retrieving build history
    history = manager.get_build_history(limit=10)
    self.assertIsInstance(history, list)

  def test_crash_history_manager(self):
    """Test CrashHistoryManager functionality."""
    manager = CrashHistoryManager(self.storage_manager, self.project_name)

    # Test storing crash data (without signature so it gets generated)
    crash_data = {
        'crash_id': 'crash_123',
        'timestamp': datetime.now().isoformat(),
        'project_name': self.project_name,
        'fuzzer_name': 'test_fuzzer',
        'crash_type': 'heap-buffer-overflow'
    }

    # First storage should succeed
    result = manager.store_crash(crash_data.copy())
    self.assertIsInstance(result, str)
    self.assertNotEqual(result, "")  # Should not be empty (not a duplicate)

    # Test duplicate detection - should be True after storing the same crash
    is_duplicate = manager.is_duplicate_crash(crash_data)
    self.assertTrue(is_duplicate)

    # Second storage should return empty string (duplicate)
    result2 = manager.store_crash(crash_data.copy())
    self.assertEqual(result2, "")

  def test_coverage_history_manager(self):
    """Test CoverageHistoryManager functionality."""
    manager = CoverageHistoryManager(self.storage_manager, self.project_name)

    # Test storing coverage data
    coverage_data = {
        'timestamp': datetime.now().isoformat(),
        'project_name': self.project_name,
        'fuzzer_name': 'test_fuzzer',
        'line_coverage': 75.5,
        'function_coverage': 80.0,
        'branch_coverage': 70.0
    }

    result = manager.store_coverage(coverage_data)
    self.assertIsInstance(result, str)

    # Test retrieving coverage history
    history = manager.get_coverage_history(limit=10)
    self.assertIsInstance(history, list)

  def test_corpus_history_manager(self):
    """Test CorpusHistoryManager functionality."""
    manager = CorpusHistoryManager(self.storage_manager, self.project_name)

    # Test storing corpus stats
    corpus_data = {
        'timestamp': datetime.now().isoformat(),
        'project_name': self.project_name,
        'fuzzer_name': 'test_fuzzer',
        'corpus_size': 1000,
        'total_size_bytes': 5000000,
        'new_files_count': 50
    }

    result = manager.store_corpus_stats(corpus_data)
    self.assertIsInstance(result, str)

    # Test retrieving corpus stats
    stats = manager.get_corpus_stats(limit=10)
    self.assertIsInstance(stats, list)


if __name__ == '__main__':
  unittest.main()
