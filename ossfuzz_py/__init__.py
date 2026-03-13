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
OSS-Fuzz Python SDK - A comprehensive SDK for interacting with OSS-Fuzz.

This package provides a clean, well-documented API for interacting with
OSS-Fuzz, enabling researchers to retrieve project information, access
historical fuzzing results, and execute customized fuzzing experiments.
"""

from .core.benchmark_manager import Benchmark, BenchmarkManager
# Data models and enums
from .core.data_models import (BuildHistoryData, CorpusHistoryData,
                               CoverageHistoryData, CrashData, CrashHistoryData,
                               FuzzingEngine, HistoricalSummary, ProjectConfig,
                               Sanitizer, Severity, TimeSeriesData)
# Core SDK - Main SDK class and modules
from .core.ossfuzz_manager import OSSFuzzManager
from .core.ossfuzz_sdk import OSSFuzzSDK
from .data.storage_adapter import (FileStorageAdapter, GCSStorageAdapter,
                                   StorageAdapter)
# Storage components
from .data.storage_manager import StorageManager
# Error handling
from .errors import *
# History managers
from .history import (BuildHistoryManager, CorpusHistoryManager,
                      CoverageHistoryManager, CrashHistoryManager,
                      HistoryManager)

# Public API - All exports available to SDK clients
__all__ = [
    # Core SDK - Main classes according to UML diagram
    'OSSFuzzManager',
    'OSSFuzzSDK',
    'BenchmarkManager',
    'Benchmark',

    # History managers
    'HistoryManager',
    'BuildHistoryManager',
    'CrashHistoryManager',
    'CorpusHistoryManager',
    'CoverageHistoryManager',

    # Storage components
    'StorageManager',
    'StorageAdapter',
    'FileStorageAdapter',
    'GCSStorageAdapter',

    # Data models and enums
    'Severity',
    'Sanitizer',
    'FuzzingEngine',
    'BuildHistoryData',
    'CrashHistoryData',
    'CorpusHistoryData',
    'CoverageHistoryData',
    'TimeSeriesData',
    'HistoricalSummary',

    # Core error types and enums
    'ErrorCode',
    'ErrorDomain',
    'OSSFuzzError',
    # Authentication errors
    'AuthenticationError',
    'InvalidCredentialsError',
    'TokenExpiredError',
    # Configuration errors
    'ConfigurationError',
    'ConfigValidationError',
    # API errors
    'APIError',
    # Network errors
    'NetworkError',
    'NetworkTimeoutError',
    'StorageConnectionError',
    # Validation errors
    'ValidationError',
    'InvalidParameterError',
    'DataAggregationError',
    'DataExportError',
    # Project errors
    'ProjectNotFoundError',
    'ProjectInfoError',
    # Fuzzing errors
    'FuzzingError',
    'FuzzRunnerError',
    'FuzzExecutionError',
    'RunConfigurationError',
    'ResultCollectionError',
    'CloudRunnerError',
    'CloudAuthError',
    'CloudApiError',
    'LocalRunnerError',
    # Rate limiting
    'RateLimitError',
    # Build errors
    'BuildSystemError',
    'BuildSystemNotFoundError',
    'BuildConfigError',
    'BuildConfigFileNotFoundError',
    'BuildConfigFormatError',
    'BuildConfigValidationError',
    'BuildIntegrationError',
    'BuildMonitorError',
    'BuilderError',
    'CloudBuildError',
    'BuildConfigurationError',
    'BuildExecutionError',
    'BuildArtifactError',
    # Storage and data errors
    'StorageManagerError',
    'StorageError',
    'StorageAdapterError',
    'HistoricalDataError',
    'HistoricalDataManagerError',
    'DataRetrievalError',
    'DataValidationError',
    'DataFetchError',
    'CacheError',
    'ResultComparisonError',
    'QueryError',
    # Analysis errors
    'ChangeTrackingError',
    'FunctionExtractionError',
    'CrashAnalysisError',
    'CoverageAnalysisError',
    # Benchmark errors
    'BenchmarkError',
    'BenchmarkValidationError',
    'UnsupportedLanguageError',
    # Metadata errors
    'MetadataError',
    'MetadataParseError',
    'MetadataValidationError',
    # Artifact errors
    'ArtifactError',
    'ArtifactNotFoundException',
    'ArtifactNotFoundError',
    'ArtifactValidationError',
    'ArtifactStorageError',
    'ArtifactIntegrityError',
    # Docker errors
    'DockerManagerError',
    'DockerExecutionError',
    'DockerImageError',
    'DockerContainerError',
    # File errors
    'FileUtilsError',
    'FilePermissionError',
    'FileFormatError',
    'WorkDirError',
    'WorkDirPermissionError',
    'WorkDirValidationError',
    # Repository errors
    'RepositoryError',
    'RepositoryNotInitializedError',
    'CloneError',
    'UpdateError',
    # Manager errors
    'OSSFuzzManagerError',
    # General/legacy errors
    'SDKError',
    'EnvironmentParametersError',
    # Utility functions
    'handle_error',
    'format_error',
    'to_dict',
]
