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
Crash history manager for the OSS-Fuzz Python SDK.

This module manages historical crash data including crash detection,
deduplication, and analysis.
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ossfuzz_py.core.data_models import CrashHistoryData, Severity
from ossfuzz_py.errors import HistoryManagerError, HistoryValidationError

from .history_manager import HistoryManager


class CrashHistoryManager(HistoryManager):
  """
  Manages historical crash data for OSS-Fuzz projects.

  This manager handles storage and retrieval of crash data including
  crash deduplication, severity analysis, and trend tracking.
  """

  @property
  def category(self) -> str:
    """Get the history category for crash data."""
    return "crash"

  def validate_data(self, data: Any) -> bool:  # pylint: disable=inconsistent-return-statements
    """
    Validate crash data before storage.

    Args:
        data: Crash data to validate

    Returns:
        bool: True if data is valid

    Raises:
        HistoryValidationError: If validation fails
    """
    try:
      if isinstance(data, dict):
        # Validate required fields
        required_fields = [
            'crash_id', 'timestamp', 'project_name', 'fuzzer_name', 'crash_type'
        ]
        for field in required_fields:
          if field not in data:
            raise HistoryValidationError(f"Missing required field: {field}")

        return True
      if isinstance(data, CrashHistoryData):
        # Pydantic model validation is automatic
        return True
      raise HistoryValidationError(f"Invalid data type: {type(data)}")
    except Exception as e:
      raise HistoryValidationError(
          f"Crash data validation failed: {str(e)}") from e

  def get_crash_history(self,
                        start_date: Optional[str] = None,
                        end_date: Optional[str] = None,
                        limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get crash history for the project.

    Args:
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)
        limit: Optional limit on number of results

    Returns:
        List of crash history entries

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      return self.get_data(self.project_name, start_date, end_date, limit)
    except Exception as e:
      raise HistoryManagerError(f"Failed to get crash history: {str(e)}")

  def is_duplicate_crash(self, crash_data: Dict[str, Any]) -> bool:
    """
    Check if a crash is a duplicate of an existing crash.

    Args:
        crash_data: Crash data to check

    Returns:
        bool: True if crash is a duplicate

    Raises:
        HistoryManagerError: If check fails
    """
    try:
      # Generate crash signature
      signature = self._generate_crash_signature(crash_data)

      # Get recent crashes to check for duplicates
      recent_crashes = self.get_crash_history(limit=1000)

      for crash in recent_crashes:
        if crash.get('crash_signature') == signature:
          return True

      return False
    except Exception as e:
      raise HistoryManagerError(
          f"Failed to check for duplicate crash: {str(e)}")

  def store_crash(self, crash_data: Dict[str, Any]) -> str:
    """
    Store a crash after deduplication check.

    Args:
        crash_data: Crash data to store

    Returns:
        str: Storage path where data was stored, or empty string if duplicate

    Raises:
        HistoryManagerError: If storage fails
    """
    try:
      # Add timestamp if not present
      if 'timestamp' not in crash_data:
        crash_data['timestamp'] = datetime.now().isoformat()

      # Add project name if not present
      if 'project_name' not in crash_data:
        crash_data['project_name'] = self.project_name

      # Generate crash signature if not present
      if 'crash_signature' not in crash_data:
        crash_data['crash_signature'] = self._generate_crash_signature(
            crash_data)

      # Check for duplicates
      if self.is_duplicate_crash(crash_data):
        self.logger.info("Duplicate crash detected, skipping storage")
        return ""

      # Validate data
      self.validate_data(crash_data)

      return self.store_data(self.project_name, crash_data)
    except Exception as e:
      raise HistoryManagerError(f"Failed to store crash: {str(e)}")

  def _parse_crashes_output(self, output: str) -> List[Dict[str, Any]]:
    """
    Parse crash output from fuzzing tools.

    Args:
        output: Raw output from fuzzing tools

    Returns:
        List of parsed crash data

    Raises:
        HistoryManagerError: If parsing fails
    """
    try:
      crashes = []

      # Simple parsing logic - this would be more sophisticated in practice
      lines = output.split('\n')
      current_crash = {}

      for line in lines:
        line = line.strip()

        if 'ERROR:' in line or 'CRASH:' in line:
          if current_crash:
            crashes.append(current_crash)
          current_crash = {
              'crash_id': self._generate_crash_id(),
              'timestamp': datetime.now().isoformat(),
              'project_name': self.project_name,
              'fuzzer_name': 'unknown',
              'crash_type': 'unknown',
              'severity': Severity.UNKNOWN.value
          }

        # Extract crash type
        if 'heap-buffer-overflow' in line.lower():
          current_crash['crash_type'] = 'heap-buffer-overflow'
          current_crash['severity'] = Severity.HIGH.value
        elif 'use-after-free' in line.lower():
          current_crash['crash_type'] = 'use-after-free'
          current_crash['severity'] = Severity.CRITICAL.value
        elif 'null-dereference' in line.lower():
          current_crash['crash_type'] = 'null-dereference'
          current_crash['severity'] = Severity.MEDIUM.value

        # Extract stack trace
        if line.startswith('#'):
          if 'stack_trace' not in current_crash:
            current_crash['stack_trace'] = line
          else:
            current_crash['stack_trace'] += '\n' + line

      # Add the last crash if any
      if current_crash:
        crashes.append(current_crash)

      return crashes
    except Exception as e:
      raise HistoryManagerError(f"Failed to parse crash output: {str(e)}")

  def _generate_crash_signature(self, crash_data: Dict[str, Any]) -> str:
    """
    Generate a unique signature for a crash.

    Args:
        crash_data: Crash data

    Returns:
        str: Crash signature hash
    """
    # Create signature from crash type and stack trace
    signature_parts = [
        crash_data.get('crash_type', ''),
        crash_data.get('fuzzer_name', ''),
    ]

    # Use first few lines of stack trace for signature
    stack_trace = crash_data.get('stack_trace', '')
    if stack_trace:
      # Take first 3 lines of stack trace
      stack_lines = stack_trace.split('\n')[:3]
      signature_parts.extend(stack_lines)

    signature_string = '|'.join(signature_parts)
    return hashlib.md5(signature_string.encode()).hexdigest()

  def _generate_crash_id(self) -> str:
    """Generate a unique crash ID."""
    import uuid
    return str(uuid.uuid4())

  def get_crash_statistics(self,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Get crash statistics for the specified period.

    Args:
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)

    Returns:
        Dictionary containing crash statistics

    Raises:
        HistoryManagerError: If calculation fails
    """
    try:
      crashes = self.get_crash_history(start_date, end_date)

      if not crashes:
        return {
            'total_crashes': 0,
            'unique_crashes': 0,
            'crash_types': {},
            'severity_distribution': {},
            'top_fuzzers': {}
        }

      # Count unique crashes by signature
      unique_signatures: Set[str] = set()
      crash_types: Dict[str, int] = {}
      severity_counts: Dict[str, int] = {}
      fuzzer_counts: Dict[str, int] = {}

      for crash in crashes:
        signature = crash.get('crash_signature', '')
        if signature:
          unique_signatures.add(signature)

        crash_type = crash.get('crash_type', 'unknown')
        crash_types[crash_type] = crash_types.get(crash_type, 0) + 1

        severity = crash.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        fuzzer = crash.get('fuzzer_name', 'unknown')
        fuzzer_counts[fuzzer] = fuzzer_counts.get(fuzzer, 0) + 1

      return {
          'total_crashes':
              len(crashes),
          'unique_crashes':
              len(unique_signatures),
          'crash_types':
              crash_types,
          'severity_distribution':
              severity_counts,
          'top_fuzzers':
              dict(
                  sorted(fuzzer_counts.items(),
                         key=lambda x: x[1],
                         reverse=True)[:10]),
          'period_start':
              start_date,
          'period_end':
              end_date
      }
    except Exception as e:
      raise HistoryManagerError(
          f"Failed to calculate crash statistics: {str(e)}")
