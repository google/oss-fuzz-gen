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
Corpus history manager for the OSS-Fuzz Python SDK.

This module manages historical corpus data including corpus growth,
statistics, and merging operations.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ossfuzz_py.core.data_models import CorpusHistoryData
from ossfuzz_py.errors import HistoryManagerError, HistoryValidationError

from .history_manager import HistoryManager


class CorpusHistoryManager(HistoryManager):
  """
  Manages historical corpus data for OSS-Fuzz projects.

  This manager handles storage and retrieval of corpus statistics including
  corpus size, growth rates, and coverage impact.
  """

  @property
  def category(self) -> str:
    """Get the history category for corpus data."""
    return "corpus"

  def validate_data(self, data: Any) -> bool:  # pylint: disable=inconsistent-return-statements
    """
    Validate corpus data before storage.

    Args:
        data: Corpus data to validate

    Returns:
        bool: True if data is valid

    Raises:
        HistoryValidationError: If validation fails
    """
    try:
      if isinstance(data, dict):
        # Validate required fields
        required_fields = [
            'timestamp', 'project_name', 'fuzzer_name', 'corpus_size'
        ]
        for field in required_fields:
          if field not in data:
            raise HistoryValidationError(f"Missing required field: {field}")

        # Validate data types
        if not isinstance(data['corpus_size'], int) or data['corpus_size'] < 0:
          raise HistoryValidationError(
              "'corpus_size' must be a non-negative integer")

        return True
      if isinstance(data, CorpusHistoryData):
        # Pydantic model validation is automatic
        return True
      raise HistoryValidationError(f"Invalid data type: {type(data)}")
    except Exception as e:
      raise HistoryValidationError(
          f"Corpus data validation failed: {str(e)}") from e

  def get_corpus_stats(self,
                       fuzzer_name: Optional[str] = None,
                       start_date: Optional[str] = None,
                       end_date: Optional[str] = None,
                       limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get corpus statistics for the project.

    Args:
        fuzzer_name: Optional fuzzer name filter
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)
        limit: Optional limit on number of results

    Returns:
        List of corpus statistics entries

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      data_name = fuzzer_name if fuzzer_name else self.project_name
      stats = self.get_data(data_name, start_date, end_date, limit)

      # Filter by fuzzer if specified and data contains multiple fuzzers
      if fuzzer_name:
        stats = [s for s in stats if s.get('fuzzer_name') == fuzzer_name]

      return stats
    except Exception as e:
      raise HistoryManagerError(f"Failed to get corpus stats: {str(e)}")

  def get_corpus_growth(self,
                        fuzzer_name: Optional[str] = None,
                        days: int = 30) -> Dict[str, Any]:
    """
    Get corpus growth statistics for the specified period.

    Args:
        fuzzer_name: Optional fuzzer name filter
        days: Number of days to analyze

    Returns:
        Dictionary containing growth statistics

    Raises:
        HistoryManagerError: If analysis fails
    """
    try:
      from datetime import timedelta

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      stats = self.get_corpus_stats(fuzzer_name=fuzzer_name,
                                    start_date=start_date.isoformat(),
                                    end_date=end_date.isoformat())

      if not stats:
        return {
            'growth_rate': 0.0,
            'size_change': 0,
            'average_size': 0.0,
            'trend': 'no_data'
        }

      # Sort by timestamp
      stats.sort(key=lambda x: x.get('timestamp', ''))

      initial_size = stats[0].get('corpus_size', 0)
      final_size = stats[-1].get('corpus_size', 0)
      size_change = final_size - initial_size

      # Calculate growth rate
      growth_rate = (size_change / initial_size *
                     100) if initial_size > 0 else 0.0

      # Calculate average size
      sizes = [s.get('corpus_size', 0) for s in stats]
      average_size = sum(sizes) / len(sizes) if sizes else 0.0

      # Determine trend
      if growth_rate > 5:
        trend = 'growing'
      elif growth_rate < -5:
        trend = 'shrinking'
      else:
        trend = 'stable'

      return {
          'growth_rate': growth_rate,
          'size_change': size_change,
          'initial_size': initial_size,
          'final_size': final_size,
          'average_size': average_size,
          'trend': trend,
          'period_days': days
      }
    except Exception as e:
      raise HistoryManagerError(f"Failed to analyze corpus growth: {str(e)}")

  def merge_corpus(self, source_path: str, target_path: str) -> Dict[str, Any]:
    """
    Merge corpus from source to target directory.

    Args:
        source_path: Path to source corpus directory
        target_path: Path to target corpus directory

    Returns:
        Dictionary containing merge results

    Raises:
        HistoryManagerError: If merge fails
    """
    try:
      source_dir = Path(source_path)
      target_dir = Path(target_path)

      if not source_dir.exists():
        raise HistoryManagerError(
            f"Source corpus directory not found: {source_path}")

      # Create target directory if it doesn't exist
      target_dir.mkdir(parents=True, exist_ok=True)

      # Count files before merge
      initial_target_count = len(list(
          target_dir.glob('*'))) if target_dir.exists() else 0
      source_count = len(list(source_dir.glob('*')))

      # Copy files from source to target
      import shutil
      copied_files = 0
      skipped_files = 0

      for source_file in source_dir.glob('*'):
        if source_file.is_file():
          target_file = target_dir / source_file.name

          # Skip if file already exists and is identical
          if target_file.exists():
            if source_file.stat().st_size == target_file.stat().st_size:
              skipped_files += 1
              continue

          shutil.copy2(source_file, target_file)
          copied_files += 1

      # Count files after merge
      final_target_count = len(list(target_dir.glob('*')))

      merge_result = {
          'initial_target_count': initial_target_count,
          'source_count': source_count,
          'copied_files': copied_files,
          'skipped_files': skipped_files,
          'final_target_count': final_target_count,
          'files_added': final_target_count - initial_target_count,
          'timestamp': datetime.now().isoformat()
      }

      # Store merge result in history
      self.store_corpus_stats({
          'timestamp': merge_result['timestamp'],
          'project_name': self.project_name,
          'fuzzer_name': 'merged',
          'corpus_size': final_target_count,
          'new_files_count': copied_files,
          'total_size_bytes': self._calculate_directory_size(target_dir)
      })

      return merge_result
    except Exception as e:
      raise HistoryManagerError(f"Failed to merge corpus: {str(e)}")

  def store_corpus_stats(self, corpus_data: Dict[str, Any]) -> str:
    """
    Store corpus statistics.

    Args:
        corpus_data: Corpus statistics to store

    Returns:
        str: Storage path where data was stored

    Raises:
        HistoryManagerError: If storage fails
    """
    try:
      # Add timestamp if not present
      if 'timestamp' not in corpus_data:
        corpus_data['timestamp'] = datetime.now().isoformat()

      # Add project name if not present
      if 'project_name' not in corpus_data:
        corpus_data['project_name'] = self.project_name

      # Validate data
      self.validate_data(corpus_data)

      # Use fuzzer name as the data identifier
      data_name = corpus_data.get('fuzzer_name', self.project_name)

      return self.store_data(data_name, corpus_data)
    except Exception as e:
      raise HistoryManagerError(f"Failed to store corpus stats: {str(e)}")

  def _calculate_directory_size(self, directory: Path) -> int:
    """
    Calculate total size of files in a directory.

    Args:
        directory: Directory path

    Returns:
        int: Total size in bytes
    """
    try:
      total_size = 0
      for file_path in directory.rglob('*'):
        if file_path.is_file():
          total_size += file_path.stat().st_size
      return total_size
    except Exception:
      return 0

  def analyze_corpus_effectiveness(self,
                                   fuzzer_name: str,
                                   days: int = 7) -> Dict[str, Any]:
    """
    Analyze corpus effectiveness in terms of coverage and crash discovery.

    Args:
        fuzzer_name: Name of the fuzzer to analyze
        days: Number of days to analyze

    Returns:
        Dictionary containing effectiveness analysis

    Raises:
        HistoryManagerError: If analysis fails
    """
    try:
      from datetime import timedelta

      end_date = datetime.now()
      start_date = end_date - timedelta(days=days)

      corpus_stats = self.get_corpus_stats(fuzzer_name=fuzzer_name,
                                           start_date=start_date.isoformat(),
                                           end_date=end_date.isoformat())

      if not corpus_stats:
        return {
            'effectiveness_score': 0.0,
            'corpus_efficiency': 0.0,
            'recommendation': 'insufficient_data'
        }

      # Calculate corpus efficiency (coverage increase per corpus size increase)
      corpus_stats.sort(key=lambda x: x.get('timestamp', ''))

      initial_stats = corpus_stats[0]
      final_stats = corpus_stats[-1]

      corpus_growth = final_stats.get('corpus_size', 0) - initial_stats.get(
          'corpus_size', 0)
      coverage_increase = final_stats.get('coverage_increase', 0.0)

      # Calculate efficiency score
      if corpus_growth > 0:
        efficiency = coverage_increase / corpus_growth
      else:
        efficiency = 0.0

      # Generate recommendation
      if efficiency > 0.1:
        recommendation = 'highly_effective'
      elif efficiency > 0.05:
        recommendation = 'moderately_effective'
      elif efficiency > 0.01:
        recommendation = 'low_effectiveness'
      else:
        recommendation = 'ineffective'

      return {
          'effectiveness_score': efficiency,
          'corpus_growth': corpus_growth,
          'coverage_increase': coverage_increase,
          'corpus_efficiency': efficiency,
          'recommendation': recommendation,
          'analysis_period_days': days
      }
    except Exception as e:
      raise HistoryManagerError(
          f"Failed to analyze corpus effectiveness: {str(e)}")
