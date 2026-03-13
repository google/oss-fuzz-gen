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
Core error definitions for the OSS-Fuzz Python SDK.

This module contains the fundamental error types, enums,
and the base OSSFuzzError dataclass.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, Optional, TypedDict


class ErrorDomain(Enum):
  """Top-level error categories for organizing error types."""
  AUTH = auto()
  NET = auto()
  CONFIG = auto()
  FUZZ = auto()
  BUILD = auto()
  STORAGE = auto()
  DATA = auto()
  ANALYSIS = auto()
  ARTIFACT = auto()
  DOCKER = auto()
  FILE = auto()
  REPOSITORY = auto()
  METADATA = auto()
  COVERAGE = auto()
  BENCHMARK = auto()
  MONITORING = auto()
  EXECUTION = auto()
  PROJECT = auto()
  VALIDATION = auto()
  API = auto()


class ErrorCode(str, Enum):
  """Fine-grained error codes within domains."""
  # Unknown/General
  UNKNOWN = "UNKNOWN"

  # Authentication errors
  TOKEN_EXPIRED = "TOKEN_EXPIRED"
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
  AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"

  # Network errors
  CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
  CONNECTION_FAILED = "CONNECTION_FAILED"
  NETWORK_ERROR = "NETWORK_ERROR"
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

  # Configuration errors
  MISSING_FIELD = "MISSING_FIELD"
  INVALID_CONFIG = "INVALID_CONFIG"
  CONFIG_VALIDATION_FAILED = "CONFIG_VALIDATION_FAILED"

  # Validation errors
  VALIDATION_FAILED = "VALIDATION_FAILED"
  INVALID_PARAMETER = "INVALID_PARAMETER"

  # API errors
  API_ERROR = "API_ERROR"

  # Project errors
  PROJECT_NOT_FOUND = "PROJECT_NOT_FOUND"
  PROJECT_INFO_ERROR = "PROJECT_INFO_ERROR"

  # Fuzzing errors
  FUZZING_FAILED = "FUZZING_FAILED"
  FUZZ_EXECUTION_ERROR = "FUZZ_EXECUTION_ERROR"
  FUZZ_CONFIG_ERROR = "FUZZ_CONFIG_ERROR"

  # Build errors
  BUILD_FAILED = "BUILD_FAILED"
  CLOUD_BUILD_FAILED = "CLOUD_BUILD_FAILED"
  BUILD_CONFIG_ERROR = "BUILD_CONFIG_ERROR"
  BUILD_EXECUTION_ERROR = "BUILD_EXECUTION_ERROR"
  BUILD_ARTIFACT_ERROR = "BUILD_ARTIFACT_ERROR"
  BUILD_SYSTEM_NOT_FOUND = "BUILD_SYSTEM_NOT_FOUND"
  BUILD_CONFIG_FILE_NOT_FOUND = "BUILD_CONFIG_FILE_NOT_FOUND"
  BUILD_CONFIG_FORMAT_ERROR = "BUILD_CONFIG_FORMAT_ERROR"
  BUILD_CONFIG_VALIDATION_ERROR = "BUILD_CONFIG_VALIDATION_ERROR"
  BUILD_INTEGRATION_ERROR = "BUILD_INTEGRATION_ERROR"
  BUILD_MONITOR_ERROR = "BUILD_MONITOR_ERROR"

  # Storage errors
  STORAGE_ERROR = "STORAGE_ERROR"
  STORAGE_CONNECTION_ERROR = "STORAGE_CONNECTION_ERROR"
  STORAGE_MANAGER_ERROR = "STORAGE_MANAGER_ERROR"

  # Data errors
  DATA_ERROR = "DATA_ERROR"
  DATA_AGGREGATION_ERROR = "DATA_AGGREGATION_ERROR"
  DATA_EXPORT_ERROR = "DATA_EXPORT_ERROR"
  DATA_RETRIEVAL_ERROR = "DATA_RETRIEVAL_ERROR"
  DATA_VALIDATION_ERROR = "DATA_VALIDATION_ERROR"
  DATA_FETCH_ERROR = "DATA_FETCH_ERROR"
  CACHE_ERROR = "CACHE_ERROR"
  RESULT_COMPARISON_ERROR = "RESULT_COMPARISON_ERROR"

  # Historical data errors
  HISTORY_MANAGER_ERROR = "HISTORY_MANAGER_ERROR"
  HISTORY_STORAGE_ERROR = "HISTORY_STORAGE_ERROR"
  HISTORY_RETRIEVAL_ERROR = "HISTORY_RETRIEVAL_ERROR"
  HISTORY_VALIDATION_ERROR = "HISTORY_VALIDATION_ERROR"

  # OSS-Fuzz SDK errors
  OSSFUZZ_SDK_ERROR = "OSSFUZZ_SDK_ERROR"
  OSSFUZZ_SDK_CONFIG_ERROR = "OSSFUZZ_SDK_CONFIG_ERROR"

  # Analysis errors
  ANALYSIS_ERROR = "ANALYSIS_ERROR"
  CHANGE_TRACKING_ERROR = "CHANGE_TRACKING_ERROR"
  FUNCTION_EXTRACTION_ERROR = "FUNCTION_EXTRACTION_ERROR"
  CRASH_ANALYSIS_ERROR = "CRASH_ANALYSIS_ERROR"

  # Coverage errors
  COVERAGE_PARSE = "COVERAGE_PARSE"
  COVERAGE_ANALYSIS_ERROR = "COVERAGE_ANALYSIS_ERROR"

  # Benchmark errors
  BENCHMARK_ERROR = "BENCHMARK_ERROR"
  BENCHMARK_VALIDATION_ERROR = "BENCHMARK_VALIDATION_ERROR"
  UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"

  # Metadata errors
  METADATA_ERROR = "METADATA_ERROR"
  METADATA_PARSE_ERROR = "METADATA_PARSE_ERROR"
  METADATA_VALIDATION_ERROR = "METADATA_VALIDATION_ERROR"

  # Artifact errors
  ARTIFACT_ERROR = "ARTIFACT_ERROR"
  ARTIFACT_NOT_FOUND = "ARTIFACT_NOT_FOUND"
  ARTIFACT_VALIDATION_ERROR = "ARTIFACT_VALIDATION_ERROR"
  ARTIFACT_STORAGE_ERROR = "ARTIFACT_STORAGE_ERROR"
  ARTIFACT_INTEGRITY_ERROR = "ARTIFACT_INTEGRITY_ERROR"

  # Docker errors
  DOCKER_ERROR = "DOCKER_ERROR"
  DOCKER_EXECUTION_ERROR = "DOCKER_EXECUTION_ERROR"
  DOCKER_IMAGE_ERROR = "DOCKER_IMAGE_ERROR"
  DOCKER_CONTAINER_ERROR = "DOCKER_CONTAINER_ERROR"

  # File errors
  FILE_ERROR = "FILE_ERROR"
  FILE_PERMISSION_ERROR = "FILE_PERMISSION_ERROR"
  FILE_FORMAT_ERROR = "FILE_FORMAT_ERROR"
  WORK_DIR_ERROR = "WORK_DIR_ERROR"
  WORK_DIR_PERMISSION_ERROR = "WORK_DIR_PERMISSION_ERROR"
  WORK_DIR_VALIDATION_ERROR = "WORK_DIR_VALIDATION_ERROR"

  # Repository errors
  REPOSITORY_ERROR = "REPOSITORY_ERROR"
  REPOSITORY_NOT_INITIALIZED = "REPOSITORY_NOT_INITIALIZED"
  CLONE_ERROR = "CLONE_ERROR"
  UPDATE_ERROR = "UPDATE_ERROR"

  # Execution errors
  EXECUTION_ERROR = "EXECUTION_ERROR"
  RUN_CONFIGURATION_ERROR = "RUN_CONFIGURATION_ERROR"
  RESULT_COLLECTION_ERROR = "RESULT_COLLECTION_ERROR"
  CLOUD_AUTH_ERROR = "CLOUD_AUTH_ERROR"
  CLOUD_API_ERROR = "CLOUD_API_ERROR"

  # Monitoring errors
  MONITORING_ERROR = "MONITORING_ERROR"

  # Query errors
  QUERY_ERROR = "QUERY_ERROR"

  # Environment parameters errors
  ENVIRONMENT_PARAMETERS_ERROR = "ENVIRONMENT_PARAMETERS_ERROR"


class ErrorDetails(TypedDict, total=False):
  """Typed dictionary for error details with optional fields."""
  endpoint: str
  status_code: int
  retry_after: int
  file: str
  line: int
  project_name: str
  target_name: str
  sanitizer: str
  build_id: str
  container_id: str
  command: str
  exit_code: int
  stderr: str
  stdout: str


@dataclass(slots=True)
class OSSFuzzError(Exception):
  """
  Base exception class for OSS-Fuzz SDK errors.

  This dataclass-based error provides a modern, type-safe foundation
  for all SDK errors with structured error information.

  Examples:
      >>> error = OSSFuzzError("Test failed", ErrorCode.VALIDATION_FAILED,
      ErrorDomain.VALIDATION)
      >>> error.retryable()
      False
      >>> error.to_dict()
      {'message': 'Test failed', 'code': 'VALIDATION_FAILED',
      'domain': 'VALIDATION', 'details': {}}
  """
  message: str
  code: ErrorCode = ErrorCode.UNKNOWN
  domain: ErrorDomain = ErrorDomain.CONFIG
  details: Optional[ErrorDetails] = None

  def __post_init__(self):
    """Initialize the Exception base class with the message."""
    Exception.__init__(self, self.message)
    if self.details is None:
      self.details = {}

  def __str__(self) -> str:
    """Return the error message."""
    return self.message

  def __repr__(self) -> str:
    """Return a detailed representation of the error."""
    return (f"OSSFuzzError(message='{self.message}', "
            f"code={self.code}, domain={self.domain})")

  def retryable(self) -> bool:
    """
    Determine if this error represents a retryable condition.

    Returns:
        True if the error condition might be temporary and worth retrying.
    """
    retryable_codes = {
        ErrorCode.CONNECTION_TIMEOUT,
        ErrorCode.CONNECTION_FAILED,
        ErrorCode.NETWORK_ERROR,
        ErrorCode.RATE_LIMIT_EXCEEDED,
        ErrorCode.STORAGE_CONNECTION_ERROR,
        ErrorCode.DOCKER_EXECUTION_ERROR,
        ErrorCode.BUILD_EXECUTION_ERROR,
    }
    return self.code in retryable_codes

  def to_dict(self) -> Dict[str, Any]:
    """
    Convert error to dictionary format for serialization.

    Returns:
        Dictionary containing error information.
    """
    return {
        'message': self.message,
        'code': self.code.value,
        'domain': self.domain.name,
        'details': self.details or {},
    }
