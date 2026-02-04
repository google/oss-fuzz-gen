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
Abstract base class for history managers.

This module defines the common interface and functionality for all
history managers in the OSS-Fuzz SDK.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, List, Optional

from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.errors import HistoryManagerError


class HistoryManager(ABC):
  """
  Abstract base class for managing historical data.

  This class provides the common interface and functionality for all
  history managers. Concrete implementations handle specific types of
  historical data (builds, crashes, corpus, coverage).

  Attributes:
      storage_manager: Storage manager for data persistence
      project_name: Name of the OSS-Fuzz project
      logger: Logger instance for this manager
  """

  def __init__(self, storage_manager: StorageManager, project_name: str):
    """
    Initialize the history manager.

    Args:
        storage_manager: Storage manager for data persistence
        project_name: Name of the OSS-Fuzz project

    Raises:
        HistoryManagerError: If initialization fails
    """
    if not storage_manager:
      raise HistoryManagerError("StorageManager is required")
    if not project_name:
      raise HistoryManagerError("Project name is required")

    self.storage_manager = storage_manager
    self.project_name = project_name
    self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    self.logger.info("Initialized %s for project: %s", self.__class__.__name__,
                     project_name)

  @property
  @abstractmethod
  def category(self) -> str:
    """
    Get the history category for this manager.

    Returns:
        str: Category name (e.g., 'build', 'crash', 'corpus', 'coverage')
    """

  def store_data(self, name: str, data: Any) -> str:
    """
    Store historical data.

    Args:
        name: Identifier for the data
        data: Data to store

    Returns:
        str: Storage path where data was stored

    Raises:
        HistoryManagerError: If storage fails
    """
    try:
      self.logger.debug("Storing %s data for %s", self.category, name)
      return self.storage_manager.store_history(self.category, name, data)
    except Exception as e:
      error_msg = f"Failed to store {self.category} data for {name}: {str(e)}"
      self.logger.error(error_msg)
      raise HistoryManagerError(error_msg)

  def get_data(self,
               name: str,
               start_date: Optional[str] = None,
               end_date: Optional[str] = None,
               limit: Optional[int] = None) -> List[Any]:
    """
    Retrieve historical data.

    Args:
        name: Identifier for the data
        start_date: Optional start date filter (ISO format)
        end_date: Optional end date filter (ISO format)
        limit: Optional limit on number of results

    Returns:
        List of historical data entries

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      self.logger.debug("Retrieving %s data for %s", self.category, name)
      return self.storage_manager.get_history(self.category, name, start_date,
                                              end_date, limit)
    except Exception as e:
      error_msg = f"Failed to get {self.category} data for {name}: {str(e)}"
      self.logger.error(error_msg)
      raise HistoryManagerError(error_msg)

  def get_latest(self, name: str) -> Optional[Any]:
    """
    Get the latest entry for the specified name.

    Args:
        name: Identifier for the data

    Returns:
        Latest data entry or None if no data exists

    Raises:
        HistoryManagerError: If retrieval fails
    """
    try:
      data = self.get_data(name, limit=1)
      return data[0] if data else None
    except Exception as e:
      error_msg = (f"Failed to get latest {self.category} data for "
                   f"{name}: {str(e)}")
      self.logger.error(error_msg)
      raise HistoryManagerError(error_msg)

  @abstractmethod
  def validate_data(self, data: Any) -> bool:
    """
    Validate data before storage.

    Args:
        data: Data to validate

    Returns:
        bool: True if data is valid

    Raises:
        HistoryManagerError: If validation fails
    """

  def _format_timestamp(self, timestamp: Any) -> str:
    """
    Format timestamp to ISO string.

    Args:
        timestamp: Timestamp to format

    Returns:
        str: ISO formatted timestamp
    """
    from datetime import datetime

    if isinstance(timestamp, str):
      return timestamp
    if isinstance(timestamp, datetime):
      return timestamp.isoformat()
    return str(timestamp)
