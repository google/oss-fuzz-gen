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
Build history manager for the OSS-Fuzz Python SDK.

This module manages historical build data including build results,
success rates, and build artifact tracking.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ossfuzz_py.core.data_models import BuildHistoryData
from ossfuzz_py.errors import HistoryManagerError, HistoryValidationError

from .history_manager import HistoryManager


class BuildHistoryManager(HistoryManager):
  """
  Manages historical build data for OSS-Fuzz projects.

  This manager handles storage and retrieval of build history, including
  build results, timing information, and artifact tracking.
  """

  @property
  def category(self) -> str:
    """Get the history category for build data."""
    return "build"

  def validate_data(self, data: Any) -> bool:  # pylint: disable=inconsistent-return-statements
    """
    Validate build data before storage.

    Args:
        data: Build data to validate

    Returns:
        bool: True if data is valid

    Raises:
        HistoryValidationError: If validation fails
    """
    try:
      if isinstance(data, dict):
        # Validate required fields
        required_fields = ['build_id', 'timestamp', 'project_name', 'success']
        for field in required_fields:
          if field not in data:
            raise HistoryValidationError(f"Missing required field: {field}")

        # Validate data types
        if not isinstance(data['success'], bool):
          raise HistoryValidationError("'success' field must be boolean")

        return True
      if isinstance(data, BuildHistoryData):
        # Pydantic model validation is automatic
        return True
      raise HistoryValidationError(f"Invalid data type: {type(data)}")
    except Exception as e:
      raise HistoryValidationError(
          f"Build data validation failed: {str(e)}") from e

  def get_build_history(self,
                        start_date: Optional[str] = None,
                        end_date: Optional[str] = None,
                        limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get build history for the project.

    Args:
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)
        limit: Optional limit on number of results

    Returns:
        List of build history entries

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      return self.get_data(self.project_name, start_date, end_date, limit)
    except Exception as e:
      raise HistoryManagerError(f"Failed to get build history: {str(e)}")

  def get_last_successful_build(self) -> Optional[Dict[str, Any]]:
    """
    Get the last successful build for the project.

    Returns:
        Last successful build data or None if no successful builds

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      # Get recent builds and find the last successful one
      builds = self.get_build_history(limit=50)  # Check last 50 builds

      for build in reversed(builds):  # Start from the most recent
        if build.get('success', False):
          return build

      return None
    except Exception as e:
      raise HistoryManagerError(
          f"Failed to get last successful build: {str(e)}")

  def store_build_result(self, build_data: Dict[str, Any]) -> str:
    """
    Store a build result.

    Args:
        build_data: Build result data to store

    Returns:
        str: Storage path where data was stored

    Raises:
        HistoryManagerError: If storage fails
    """
    try:
      # Add a timestamp if not present
      if 'timestamp' not in build_data:
        build_data['timestamp'] = datetime.now().isoformat()

      # Add a project name if not present
      if 'project_name' not in build_data:
        build_data['project_name'] = self.project_name

      # Validate data
      self.validate_data(build_data)

      return self.store_data(self.project_name, build_data)
    except Exception as e:
      raise HistoryManagerError(f"Failed to store build result: {str(e)}")

  def get_build_statistics(self,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Get build statistics for the specified period.

    Args:
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)

    Returns:
        Dictionary containing build statistics

    Raises:
        HistoryManagerError: If calculation fails
    """
    try:
      builds = self.get_build_history(start_date, end_date)

      if not builds:
        return {
            'total_builds': 0,
            'successful_builds': 0,
            'failed_builds': 0,
            'success_rate': 0.0,
            'average_duration': 0.0
        }

      total_builds = len(builds)
      successful_builds = sum(
          1 for build in builds if build.get('success', False))
      failed_builds = total_builds - successful_builds
      success_rate = (successful_builds /
                      total_builds) * 100 if total_builds > 0 else 0.0

      # Calculate average duration for builds with duration data
      durations = [
          build.get('duration_seconds', 0)
          for build in builds
          if build.get('duration_seconds') is not None
      ]
      average_duration = sum(durations) / len(durations) if durations else 0.0

      return {
          'total_builds': total_builds,
          'successful_builds': successful_builds,
          'failed_builds': failed_builds,
          'success_rate': success_rate,
          'average_duration': average_duration,
          'period_start': start_date,
          'period_end': end_date
      }
    except Exception as e:
      raise HistoryManagerError(
          f"Failed to calculate build statistics: {str(e)}")

  def get_build_trends(self, days: int = 30) -> Dict[str, Any]:
    """
    Get build trends for the specified number of days.

    Args:
        days: Number of days to analyze

    Returns:
        Dictionary containing trend analysis

    Raises:
        HistoryManagerError: If analysis fails
    """
    try:
      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      builds = self.get_build_history(start_date=start_date.isoformat(),
                                      end_date=end_date.isoformat())

      if not builds:
        return {'trend': 'no_data', 'builds_per_day': 0.0}

      # Group builds by day
      daily_builds = {}
      for build in builds:
        build_date = build.get('timestamp', '')[:10]  # Get YYYY-MM-DD
        if build_date not in daily_builds:
          daily_builds[build_date] = {'total': 0, 'successful': 0}
        daily_builds[build_date]['total'] += 1
        if build.get('success', False):
          daily_builds[build_date]['successful'] += 1

      # Calculate trends
      total_days = len(daily_builds)
      builds_per_day = len(builds) / days if days > 0 else 0.0

      # Calculate success rate trend
      daily_success_rates = []
      for day_data in daily_builds.values():
        rate = (day_data['successful'] /
                day_data['total']) * 100 if day_data['total'] > 0 else 0.0
        daily_success_rates.append(rate)

      # Simple trend analysis
      if len(daily_success_rates) >= 2:
        recent_rate = sum(daily_success_rates[-7:]) / min(
            7, len(daily_success_rates))
        older_rate = sum(daily_success_rates[:-7]) / max(
            1,
            len(daily_success_rates) - 7)

        if recent_rate > older_rate + 5:
          trend = 'improving'
        elif recent_rate < older_rate - 5:
          trend = 'declining'
        else:
          trend = 'stable'
      else:
        trend = 'insufficient_data'

      return {
          'trend':
              trend,
          'builds_per_day':
              builds_per_day,
          'total_days_with_builds':
              total_days,
          'average_success_rate':
              sum(daily_success_rates) /
              len(daily_success_rates) if daily_success_rates else 0.0
      }
    except Exception as e:
      raise HistoryManagerError(f"Failed to analyze build trends: {str(e)}")
