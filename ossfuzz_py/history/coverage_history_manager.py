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
Coverage history manager for the OSS-Fuzz Python SDK.

This module manages historical coverage data including coverage trends,
analysis, and reporting.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ossfuzz_py.core.data_models import CoverageHistoryData
from ossfuzz_py.errors import HistoryManagerError, HistoryValidationError

from .history_manager import HistoryManager


class CoverageHistoryManager(HistoryManager):
  """
  Manages historical coverage data for OSS-Fuzz projects.

  This manager handles storage and retrieval of coverage data including
  line coverage, function coverage, and branch coverage trends.
  """

  @property
  def category(self) -> str:
    """Get the history category for coverage data."""
    return "coverage"

  def validate_data(self, data: Any) -> bool:  # pylint: disable=inconsistent-return-statements
    """
    Validate coverage data before storage.

    Args:
        data: Coverage data to validate

    Returns:
        bool: True if data is valid

    Raises:
        HistoryValidationError: If validation fails
    """
    try:
      if isinstance(data, dict):
        # Validate required fields
        required_fields = ['timestamp', 'project_name', 'line_coverage']
        for field in required_fields:
          if field not in data:
            raise HistoryValidationError(f"Missing required field: {field}")

        # Validate coverage percentages
        coverage_fields = [
            'line_coverage', 'function_coverage', 'branch_coverage'
        ]
        for field in coverage_fields:
          if field in data:
            value = data[field]
            if not isinstance(value, (int, float)) or value < 0 or value > 100:
              raise HistoryValidationError(
                  f"'{field}' must be between 0 and 100")

        return True
      if isinstance(data, CoverageHistoryData):
        # Pydantic model validation is automatic
        return True
      raise HistoryValidationError(f"Invalid data type: {type(data)}")
    except Exception as e:
      raise HistoryValidationError(
          f"Coverage data validation failed: {str(e)}") from e

  def get_coverage_history(self,
                           fuzzer_name: Optional[str] = None,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None,
                           limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get coverage history for the project.

    Args:
        fuzzer_name: Optional fuzzer name filter
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)
        limit: Optional limit on number of results

    Returns:
        List of coverage history entries

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      data_name = fuzzer_name if fuzzer_name else self.project_name
      history = self.get_data(data_name, start_date, end_date, limit)

      # Filter by fuzzer if specified and data contains multiple fuzzers
      if fuzzer_name:
        history = [h for h in history if h.get('fuzzer_name') == fuzzer_name]

      return history
    except Exception as e:
      raise HistoryManagerError(f"Failed to get coverage history: {str(e)}")

  def get_latest_coverage(self,
                          fuzzer_name: Optional[str] = None
                         ) -> Optional[Dict[str, Any]]:
    """
    Get the latest coverage data for the project.

    Args:
        fuzzer_name: Optional fuzzer name filter

    Returns:
        Latest coverage data or None if no data exists

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      history = self.get_coverage_history(fuzzer_name=fuzzer_name, limit=1)
      return history[0] if history else None
    except Exception as e:
      raise HistoryManagerError(f"Failed to get latest coverage: {str(e)}")

  def get_coverage_report(self,
                          start_date: Optional[str] = None,
                          end_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a comprehensive coverage report for the specified period.

    Args:
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)

    Returns:
        Dictionary containing coverage report

    Raises:
        HistoryManagerError: If report generation fails
    """
    try:
      history = self.get_coverage_history(start_date=start_date,
                                          end_date=end_date)

      if not history:
        return {
            'summary': {
                'total_measurements': 0,
                'max_line_coverage': 0.0,
                'avg_line_coverage': 0.0,
                'coverage_trend': 'no_data'
            },
            'details': [],
            'recommendations': ['No coverage data available']
        }

      # Sort by timestamp
      history.sort(key=lambda x: x.get('timestamp', ''))

      # Calculate summary statistics
      line_coverages = [h.get('line_coverage', 0.0) for h in history]
      function_coverages = [
          h.get('function_coverage', 0.0)
          for h in history
          if h.get('function_coverage') is not None
      ]
      branch_coverages = [
          h.get('branch_coverage', 0.0)
          for h in history
          if h.get('branch_coverage') is not None
      ]

      max_line_coverage = max(line_coverages) if line_coverages else 0.0
      avg_line_coverage = sum(line_coverages) / len(
          line_coverages) if line_coverages else 0.0

      # Analyze trend
      if len(line_coverages) >= 2:
        recent_avg = sum(line_coverages[-5:]) / min(5, len(line_coverages))
        older_avg = sum(line_coverages[:-5]) / max(1, len(line_coverages) - 5)

        if recent_avg > older_avg + 1:
          trend = 'improving'
        elif recent_avg < older_avg - 1:
          trend = 'declining'
        else:
          trend = 'stable'
      else:
        trend = 'insufficient_data'

      # Generate recommendations
      recommendations = []
      if max_line_coverage < 50:
        recommendations.append(
            "Line coverage is below 50%. Consider adding more test cases.")
      if function_coverages and max(function_coverages) < 70:
        recommendations.append(
            "Function coverage could be improved. Focus on uncovered functions."
        )
      if trend == 'declining':
        recommendations.append(
            "Coverage trend is declining. Review recent changes.")
      if not recommendations:
        recommendations.append(
            "Coverage metrics look good. Continue current testing approach.")

      return {
          'summary': {
              'total_measurements':
                  len(history),
              'max_line_coverage':
                  max_line_coverage,
              'avg_line_coverage':
                  avg_line_coverage,
              'max_function_coverage':
                  max(function_coverages) if function_coverages else None,
              'avg_function_coverage':
                  sum(function_coverages) /
                  len(function_coverages) if function_coverages else None,
              'max_branch_coverage':
                  max(branch_coverages) if branch_coverages else None,
              'avg_branch_coverage':
                  sum(branch_coverages) /
                  len(branch_coverages) if branch_coverages else None,
              'coverage_trend':
                  trend,
              'period_start':
                  start_date,
              'period_end':
                  end_date
          },
          'details': history,
          'recommendations': recommendations
      }
    except Exception as e:
      raise HistoryManagerError(f"Failed to generate coverage report: {str(e)}")

  def store_coverage(self, coverage_data: Dict[str, Any]) -> str:
    """
    Store coverage data.

    Args:
        coverage_data: Coverage data to store

    Returns:
        str: Storage path where data was stored

    Raises:
        HistoryManagerError: If storage fails
    """
    try:
      # Add timestamp if not present
      if 'timestamp' not in coverage_data:
        coverage_data['timestamp'] = datetime.now().isoformat()

      # Add project name if not present
      if 'project_name' not in coverage_data:
        coverage_data['project_name'] = self.project_name

      # Validate data
      self.validate_data(coverage_data)

      # Use fuzzer name as the data identifier if available
      data_name = coverage_data.get('fuzzer_name', self.project_name)

      return self.store_data(data_name, coverage_data)
    except Exception as e:
      raise HistoryManagerError(f"Failed to store coverage data: {str(e)}")

  def analyze_coverage_trends(self, days: int = 30) -> Dict[str, Any]:
    """
    Analyze coverage trends for the specified number of days.

    Args:
        days: Number of days to analyze

    Returns:
        Dictionary containing trend analysis

    Raises:
        HistoryManagerError: If analysis fails
    """
    try:
      from datetime import timedelta

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      history = self.get_coverage_history(start_date=start_date.isoformat(),
                                          end_date=end_date.isoformat())

      if not history:
        return {
            'trend': 'no_data',
            'coverage_velocity': 0.0,
            'stability': 'unknown'
        }

      # Sort by timestamp
      history.sort(key=lambda x: x.get('timestamp', ''))

      line_coverages = [h.get('line_coverage', 0.0) for h in history]

      # Calculate coverage velocity (change per day)
      if len(line_coverages) >= 2:
        coverage_change = line_coverages[-1] - line_coverages[0]
        coverage_velocity = coverage_change / days
      else:
        coverage_velocity = 0.0

      # Calculate stability (variance in coverage)
      if len(line_coverages) > 1:
        mean_coverage = sum(line_coverages) / len(line_coverages)
        variance = sum((x - mean_coverage)**2
                       for x in line_coverages) / len(line_coverages)
        std_dev = variance**0.5

        if std_dev < 1.0:
          stability = 'stable'
        elif std_dev < 3.0:
          stability = 'moderate'
        else:
          stability = 'unstable'
      else:
        stability = 'unknown'

      # Determine overall trend
      if coverage_velocity > 0.1:
        trend = 'improving'
      elif coverage_velocity < -0.1:
        trend = 'declining'
      else:
        trend = 'stable'

      return {
          'trend': trend,
          'coverage_velocity': coverage_velocity,
          'stability': stability,
          'current_coverage': line_coverages[-1] if line_coverages else 0.0,
          'max_coverage': max(line_coverages) if line_coverages else 0.0,
          'min_coverage': min(line_coverages) if line_coverages else 0.0,
          'analysis_period_days': days
      }
    except Exception as e:
      raise HistoryManagerError(f"Failed to analyze coverage trends: {str(e)}")

  def compare_coverage(self,
                       baseline_date: str,
                       comparison_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Compare coverage between two time points.

    Args:
        baseline_date: Baseline date for comparison (ISO format)
        comparison_date: Comparison date (ISO format), defaults to latest

    Returns:
        Dictionary containing comparison results

    Raises:
        HistoryManagerError: If comparison fails
    """
    try:
      # Get baseline coverage
      baseline_history = self.get_coverage_history(start_date=baseline_date,
                                                   end_date=baseline_date,
                                                   limit=1)

      if not baseline_history:
        raise HistoryManagerError(
            f"No coverage data found for baseline date: {baseline_date}")

      baseline_coverage = baseline_history[0]

      # Get comparison coverage
      if comparison_date:
        comparison_history = self.get_coverage_history(
            start_date=comparison_date, end_date=comparison_date, limit=1)
      else:
        comparison_history = self.get_coverage_history(limit=1)

      if not comparison_history:
        raise HistoryManagerError("No coverage data found for comparison")

      comparison_coverage = comparison_history[0]

      # Calculate differences
      line_diff = comparison_coverage.get(
          'line_coverage', 0.0) - baseline_coverage.get('line_coverage', 0.0)
      function_diff = None
      branch_diff = None

      if (comparison_coverage.get('function_coverage') is not None and
          baseline_coverage.get('function_coverage') is not None):
        function_diff = comparison_coverage[
            'function_coverage'] - baseline_coverage['function_coverage']

      if (comparison_coverage.get('branch_coverage') is not None and
          baseline_coverage.get('branch_coverage') is not None):
        branch_diff = comparison_coverage[
            'branch_coverage'] - baseline_coverage['branch_coverage']

      return {
          'baseline': baseline_coverage,
          'comparison': comparison_coverage,
          'differences': {
              'line_coverage': line_diff,
              'function_coverage': function_diff,
              'branch_coverage': branch_diff
          },
          'improvement': line_diff > 0,
          'significant_change': abs(line_diff) > 1.0
      }
    except Exception as e:
      raise HistoryManagerError(f"Failed to compare coverage: {str(e)}")
