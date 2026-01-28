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
OSS-Fuzz Historical Data SDK.

This module provides the main SDK facade for accessing and analyzing
historical OSS-Fuzz data including builds, crashes, corpus, and coverage.
"""

import logging
from typing import Any, Dict, Optional

from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.errors import OSSFuzzSDKConfigError, OSSFuzzSDKError
from ossfuzz_py.history import (BuildHistoryManager, CorpusHistoryManager,
                                CoverageHistoryManager, CrashHistoryManager)
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.env_vars import EnvVars


class OSSFuzzSDK:
  """
  Main SDK facade for OSS-Fuzz historical data access and analysis.

  This class provides a unified interface for accessing historical data
  across different categories (builds, crashes, corpus, coverage) and
  generating comprehensive reports and analyses.

  Example:
      ```python
      # Initialize SDK
      config = {
          'storage_backend': 'local',
          'storage_path': '/path/to/data'
      }
      sdk = OSSFuzzSDK('libpng', config)

      # Generate project report
      report = sdk.generate_project_report()

      # Analyze fuzzing efficiency
      efficiency = sdk.analyze_fuzzing_efficiency()
      ```
  """

  def __init__(self,
               project_name: str,
               config: Optional[Dict[str, Any]] = None):
    """
    Initialize the OSS-Fuzz SDK.

    Args:
        project_name: Name of the OSS-Fuzz project
        config: Configuration dictionary for storage and other settings

    Raises:
        OSSFuzzSDKConfigError: If configuration is invalid
        OSSFuzzSDKError: If initialization fails
    """
    self.project_name = project_name
    self.config = config or {}
    self.logger = logging.getLogger(f"{__name__}.{project_name}")

    try:
      if not project_name:
        raise OSSFuzzSDKConfigError("Project name is required")

      # Merge environment variables into config
      self._load_config_from_env()

      # Initialize storage manager
      self.storage = StorageManager(self.config)

      # Initialize history managers
      self.build = BuildHistoryManager(self.storage, project_name)
      self.crash = CrashHistoryManager(self.storage, project_name)
      self.corpus = CorpusHistoryManager(self.storage, project_name)
      self.coverage = CoverageHistoryManager(self.storage, project_name)

      self.logger.info("Initialized OSSFuzzSDK "
                       "for project: %s", project_name)

    except OSSFuzzSDKConfigError:
      # Re-raise config errors as-is
      raise
    except Exception as e:
      error_msg = (f"Failed to initialize OSSFuzzSDK "
                   f"for {project_name}: {str(e)}")
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg) from e

  def _load_config_from_env(self) -> None:
    """Load configuration from environment variables."""
    try:
      # Storage configuration
      storage_backend = EnvUtils.get_env(
          EnvVars.OSSFUZZ_HISTORY_STORAGE_BACKEND)
      if storage_backend:
        self.config['storage_backend'] = storage_backend

      storage_path = EnvUtils.get_env(EnvVars.OSSFUZZ_HISTORY_STORAGE_PATH)
      if storage_path:
        self.config['storage_path'] = storage_path

      # GCS configuration
      gcs_bucket = EnvUtils.get_env(EnvVars.GCS_BUCKET_NAME)
      if gcs_bucket:
        self.config['gcs_bucket_name'] = gcs_bucket

    except Exception as e:
      self.logger.warning("Failed to load some environment variables: %s",
                          str(e))

  def generate_project_report(
      self,
      days: int = 30,
      include_details: bool = True  # pylint: disable=unused-argument
  ) -> Dict[str, Any]:
    """
    Generate a comprehensive project report.

    Args:
        days: Number of days to include in the report
        include_details: Whether to include detailed data

    Returns:
        Dictionary containing comprehensive project report

    Raises:
        OSSFuzzSDKError: If report generation fails
    """
    try:
      from datetime import datetime, timedelta

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)
      start_date_str = start_date.isoformat()
      end_date_str = end_date.isoformat()

      self.logger.info("Generating project report for %s (%d days)",
                       self.project_name, days)

      report = {
          'project_name': self.project_name,
          'report_generated': end_date.isoformat(),
          'period': {
              'start_date': start_date_str,
              'end_date': end_date_str,
              'days': days
          }
      }

      # Build statistics
      try:
        build_stats = self.build.get_build_statistics(start_date_str,
                                                      end_date_str)
        build_trends = self.build.get_build_trends(days)
        report['build_summary'] = {
            'statistics': build_stats,
            'trends': build_trends
        }
      except Exception as e:
        self.logger.warning("Failed to get build data: %s", str(e))
        report['build_summary'] = {'error': str(e)}

      # Crash statistics
      try:
        crash_stats = self.crash.get_crash_statistics(start_date_str,
                                                      end_date_str)
        report['crash_summary'] = crash_stats
      except Exception as e:
        self.logger.warning("Failed to get crash data: %s", str(e))
        report['crash_summary'] = {'error': str(e)}

      # Coverage analysis
      try:
        coverage_report = self.coverage.get_coverage_report(
            start_date_str, end_date_str)
        coverage_trends = self.coverage.analyze_coverage_trends(days)
        report['coverage_summary'] = {
            'report': coverage_report,
            'trends': coverage_trends
        }
      except Exception as e:
        self.logger.warning("Failed to get coverage data: %s", str(e))
        report['coverage_summary'] = {'error': str(e)}

      # Corpus analysis
      try:
        corpus_growth = self.corpus.get_corpus_growth(days=days)
        report['corpus_summary'] = {'growth': corpus_growth}
      except Exception as e:
        self.logger.warning("Failed to get corpus data: %s", str(e))
        report['corpus_summary'] = {'error': str(e)}

      # Overall health score
      report['health_score'] = self._calculate_health_score(report)

      return report

    except Exception as e:
      error_msg = f"Failed to generate project report: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)

  def analyze_fuzzing_efficiency(self, days: int = 30) -> Dict[str, Any]:
    """
    Analyze overall fuzzing efficiency for the project.

    Args:
        days: Number of days to analyze

    Returns:
        Dictionary containing efficiency analysis

    Raises:
        OSSFuzzSDKError: If analysis fails
    """
    try:
      self.logger.info("Analyzing fuzzing efficiency for %s (%d days)",
                       self.project_name, days)

      from datetime import datetime, timedelta

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      analysis = {
          'project_name': self.project_name,
          'analysis_date': end_date.isoformat(),
          'period_days': days
      }

      # Build efficiency
      build_trends = self.build.get_build_trends(days)
      analysis['build_efficiency'] = {
          'builds_per_day': build_trends.get('builds_per_day', 0.0),
          'success_rate': build_trends.get('average_success_rate', 0.0),
          'trend': build_trends.get('trend', 'unknown')
      }

      # Coverage efficiency
      coverage_trends = self.coverage.analyze_coverage_trends(days)
      analysis['coverage_efficiency'] = {
          'coverage_velocity': coverage_trends.get('coverage_velocity', 0.0),
          'stability': coverage_trends.get('stability', 'unknown'),
          'current_coverage': coverage_trends.get('current_coverage', 0.0)
      }

      # Crash discovery efficiency
      crash_stats = self.crash.get_crash_statistics(start_date.isoformat(),
                                                    end_date.isoformat())
      total_crashes = crash_stats.get('total_crashes', 0)
      unique_crashes = crash_stats.get('unique_crashes', 0)

      analysis['crash_efficiency'] = {
          'crashes_per_day':
              total_crashes / days if days > 0 else 0.0,
          'unique_crash_rate': (unique_crashes / total_crashes *
                                100) if total_crashes > 0 else 0.0,
          'total_crashes':
              total_crashes,
          'unique_crashes':
              unique_crashes
      }

      # Corpus efficiency
      corpus_growth = self.corpus.get_corpus_growth(days=days)
      analysis['corpus_efficiency'] = {
          'growth_rate': corpus_growth.get('growth_rate', 0.0),
          'size_change': corpus_growth.get('size_change', 0),
          'trend': corpus_growth.get('trend', 'unknown')
      }

      # Overall efficiency score
      analysis['overall_efficiency'] = self._calculate_efficiency_score(
          analysis)

      return analysis

    except Exception as e:
      error_msg = f"Failed to analyze fuzzing efficiency: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)

  def _calculate_health_score(self, report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall project health score based on report data.

    Args:
        report: Project report data

    Returns:
        Dictionary containing health score and breakdown
    """
    try:
      scores = {}
      weights = {}

      # Build health (30% weight)
      build_summary = report.get('build_summary', {})
      if 'statistics' in build_summary:
        build_success_rate = build_summary['statistics'].get(
            'success_rate', 0.0)
        scores['build'] = min(build_success_rate, 100.0)
        weights['build'] = 0.3

      # Coverage health (40% weight)
      coverage_summary = report.get('coverage_summary', {})
      if 'report' in coverage_summary:
        max_coverage = coverage_summary['report']['summary'].get(
            'max_line_coverage', 0.0)
        scores['coverage'] = min(max_coverage, 100.0)
        weights['coverage'] = 0.4

      # Crash health (20% weight) - inverse scoring
      crash_summary = report.get('crash_summary', {})
      total_crashes = crash_summary.get('total_crashes', 0)
      if total_crashes == 0:
        scores['crash'] = 100.0
      else:
        # Lower score for more crashes
        scores['crash'] = max(0.0, 100.0 - min(total_crashes, 100))
      weights['crash'] = 0.2

      # Corpus health (10% weight)
      corpus_summary = report.get('corpus_summary', {})
      if 'growth' in corpus_summary:
        growth_rate = corpus_summary['growth']['growth_rate']
        if growth_rate > 0:
          scores['corpus'] = min(100.0, 50.0 + growth_rate * 10)
        else:
          scores['corpus'] = 50.0
        weights['corpus'] = 0.1

      # Calculate weighted average
      total_score = 0.0
      total_weight = 0.0

      for category, score in scores.items():
        weight = weights.get(category, 0.0)
        total_score += score * weight
        total_weight += weight

      overall_score = total_score / total_weight if total_weight > 0 else 0.0

      # Determine health status
      if overall_score >= 80:
        status = 'excellent'
      elif overall_score >= 60:
        status = 'good'
      elif overall_score >= 40:
        status = 'fair'
      else:
        status = 'poor'

      return {
          'overall_score': round(overall_score, 2),
          'status': status,
          'category_scores': scores,
          'weights': weights
      }
    except Exception as e:
      self.logger.warning("Failed to calculate health score: %s", str(e))
      return {'overall_score': 0.0, 'status': 'unknown', 'error': str(e)}

  def _calculate_efficiency_score(self, analysis: Dict[str,
                                                       Any]) -> Dict[str, Any]:
    """
    Calculate overall efficiency score based on analysis data.

    Args:
        analysis: Efficiency analysis data

    Returns:
        Dictionary containing efficiency score and breakdown
    """
    try:
      scores = {}

      # Build efficiency
      build_eff = analysis.get('build_efficiency', {})
      builds_per_day = build_eff.get('builds_per_day', 0.0)
      success_rate = build_eff.get('success_rate', 0.0)

      # Score based on build frequency and success rate
      build_score = min(100.0, (builds_per_day * 10) + success_rate)
      scores['build'] = build_score

      # Coverage efficiency
      coverage_eff = analysis.get('coverage_efficiency', {})
      coverage_velocity = coverage_eff.get('coverage_velocity', 0.0)
      current_coverage = coverage_eff.get('current_coverage', 0.0)

      # Score based on coverage growth and current level
      coverage_score = min(100.0, current_coverage + (coverage_velocity * 20))
      scores['coverage'] = max(0.0, coverage_score)

      # Crash efficiency
      crash_eff = analysis.get('crash_efficiency', {})
      unique_crash_rate = crash_eff.get('unique_crash_rate', 0.0)
      crashes_per_day = crash_eff.get('crashes_per_day', 0.0)

      # Higher score for finding unique crashes efficiently
      crash_score = min(100.0, unique_crash_rate + min(crashes_per_day * 5, 20))
      scores['crash'] = crash_score

      # Corpus efficiency
      corpus_eff = analysis.get('corpus_efficiency', {})
      growth_rate = corpus_eff.get('growth_rate', 0.0)

      # Score based on corpus growth
      corpus_score = min(100.0, 50.0 + max(-50.0, min(50.0, growth_rate * 2)))
      scores['corpus'] = corpus_score

      # Calculate overall efficiency
      overall_efficiency = sum(scores.values()) / len(scores) if scores else 0.0

      # Determine efficiency level
      if overall_efficiency >= 75:
        level = 'high'
      elif overall_efficiency >= 50:
        level = 'medium'
      elif overall_efficiency >= 25:
        level = 'low'
      else:
        level = 'very_low'

      return {
          'overall_efficiency': round(overall_efficiency, 2),
          'level': level,
          'category_scores': scores
      }
    except Exception as e:
      self.logger.warning("Failed to calculate efficiency score: %s", str(e))
      return {'overall_efficiency': 0.0, 'level': 'unknown', 'error': str(e)}

  def get_project_summary(self) -> Dict[str, Any]:
    """
    Get a quick summary of the project's current state.

    Returns:
        Dictionary containing project summary

    Raises:
        OSSFuzzSDKError: If summary generation fails
    """
    try:
      from datetime import datetime

      summary: Dict[str, Any] = {
          'project_name': self.project_name,
          'summary_date': datetime.now().isoformat()
      }

      # Latest build status
      try:
        last_build = self.build.get_last_successful_build()
        summary['last_successful_build'] = str(
            last_build) if last_build else 'None'
      except Exception as e:
        summary['last_successful_build'] = f'error: {str(e)}'

      # Latest coverage
      try:
        latest_coverage = self.coverage.get_latest_coverage()
        summary['latest_coverage'] = str(
            latest_coverage) if latest_coverage else 'None'
      except Exception as e:
        summary['latest_coverage'] = f'error: {str(e)}'

      # Recent crash count
      try:
        from datetime import timedelta
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        recent_crashes = self.crash.get_crash_history(start_date=week_ago)
        summary['recent_crashes'] = len(recent_crashes)
      except Exception as e:
        summary['recent_crashes'] = f'error: {str(e)}'

      return summary

    except Exception as e:
      error_msg = f"Failed to get project summary: {str(e)}"
      self.logger.error(error_msg)
      raise OSSFuzzSDKError(error_msg)
