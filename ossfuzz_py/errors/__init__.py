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
OSS-Fuzz Python SDK Error Handling Module.

This module provides a modern, type-safe, and extensible error handling system
for the OSS-Fuzz Python SDK. It includes:

- Structured error types with domains and codes
- Dynamic error subclass generation
- Comprehensive error formatting and conversion utilities
- Backward compatibility with the original error API

Public API:
    - All error classes (OSSFuzzError, AuthenticationError, etc.)
    - Error enums (ErrorCode, ErrorDomain)
    - Utility functions (handle_error, format_error, to_dict)
"""

# Core error types and enums
from .core import ErrorCode, ErrorDetails, ErrorDomain, OSSFuzzError

# All generated error classes from factory
from .factory import *

# Formatting and conversion utilities
from .formatting import (
    format_error,
    format_error_json,
    format_error_legacy,
    format_error_simple,
    get_error_category,
    handle_error,
    is_retryable_error,
    to_dict,
)

# Backward compatibility aliases
# The original errors.py had these function names
format_error_original = format_error_legacy  # Original format_error behavior

# All public symbols for __all__
__all__ = [
    # Core types and enums
    "ErrorDomain",
    "ErrorCode",
    "ErrorDetails",
    "OSSFuzzError",
    # Authentication errors
    "AuthenticationError",
    "InvalidCredentialsError",
    "TokenExpiredError",
    # Configuration errors
    "ConfigurationError",
    "ConfigValidationError",
    # API errors
    "APIError",
    # Network errors
    "NetworkError",
    "NetworkTimeoutError",
    "StorageConnectionError",
    # Validation errors
    "ValidationError",
    "InvalidParameterError",
    "DataAggregationError",
    "DataExportError",
    # Project errors
    "ProjectNotFoundError",
    "ProjectInfoError",
    # Fuzzing errors
    "FuzzingError",
    "FuzzRunnerError",
    "FuzzExecutionError",
    "RunConfigurationError",
    "ResultCollectionError",
    "CloudRunnerError",
    "CloudAuthError",
    "CloudApiError",
    "LocalRunnerError",
    # Rate limiting
    "RateLimitError",
    # Build errors
    "BuildSystemError",
    "BuildSystemNotFoundError",
    "BuildConfigError",
    "BuildConfigFileNotFoundError",
    "BuildConfigFormatError",
    "BuildConfigValidationError",
    "BuildIntegrationError",
    "BuildMonitorError",
    "BuilderError",
    "CloudBuildError",
    "BuildConfigurationError",
    "BuildExecutionError",
    "BuildArtifactError",
    # Storage and data errors
    "StorageManagerError",
    "StorageError",
    "StorageAdapterError",
    "HistoricalDataError",
    "HistoricalDataManagerError",
    "DataRetrievalError",
    "DataValidationError",
    "DataFetchError",
    "CacheError",
    "ResultComparisonError",
    "QueryError",
    # Analysis errors
    "ChangeTrackingError",
    "FunctionExtractionError",
    "CrashAnalysisError",
    "CoverageAnalysisError",
    # Benchmark errors
    "BenchmarkError",
    "BenchmarkValidationError",
    "UnsupportedLanguageError",
    # Metadata errors
    "MetadataError",
    "MetadataParseError",
    "MetadataValidationError",
    # Artifact errors
    "ArtifactError",
    "ArtifactNotFoundException",
    "ArtifactNotFoundError",
    "ArtifactValidationError",
    "ArtifactStorageError",
    "ArtifactIntegrityError",
    # Docker errors
    "DockerManagerError",
    "DockerExecutionError",
    "DockerImageError",
    "DockerContainerError",
    # File errors
    "FileUtilsError",
    "FilePermissionError",
    "FileFormatError",
    "WorkDirError",
    "WorkDirPermissionError",
    "WorkDirValidationError",
    # Repository errors
    "RepositoryError",
    "RepositoryNotInitializedError",
    "CloneError",
    "UpdateError",
    # Manager errors
    "OSSFuzzManagerError",
    # General/legacy errors
    "SDKError",
    "EnvironmentParametersError",
    # Utility functions
    "handle_error",
    "to_dict",
    "format_error",
    "format_error_simple",
    "format_error_json",
    "is_retryable_error",
    "get_error_category",
    # Factory utilities
    "make_error",
    "get_error_class",
    "list_error_classes",
]
