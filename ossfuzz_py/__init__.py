"""
OSS-Fuzz Python SDK - A comprehensive SDK for interacting with OSS-Fuzz.

This package provides a clean, well-documented API for interacting with OSS-Fuzz,
enabling researchers to retrieve project information, access historical fuzzing
results, and execute customized fuzzing experiments.
"""

# Core SDK - Main SDK class and modules
from .core.ossfuzz_manager import OSSFuzzManager
from .core.benchmark_manager import BenchmarkManager, Benchmark

# Data models and enums
from .core.data_models import (
    Sanitizer, FuzzingEngine, Severity
)

# Error handling
from .core.errors import (
    # Core error types and enums
    ErrorCode, ErrorDomain, OSSFuzzError,
    # Authentication errors
    AuthenticationError, InvalidCredentialsError, TokenExpiredError,
    # Configuration errors
    ConfigurationError, ConfigValidationError,
    # API errors
    APIError,
    # Network errors
    NetworkError, NetworkTimeoutError, StorageConnectionError,
    # Validation errors
    ValidationError, InvalidParameterError, DataAggregationError, DataExportError,
    # Project errors
    ProjectNotFoundError, ProjectInfoError,
    # Fuzzing errors
    FuzzingError, FuzzRunnerError, FuzzExecutionError, RunConfigurationError,
    ResultCollectionError, CloudRunnerError, CloudAuthError, CloudApiError, LocalRunnerError,
    # Rate limiting
    RateLimitError,
    # Build errors
    BuildSystemError, BuildSystemNotFoundError, BuildConfigError,
    BuildConfigFileNotFoundError, BuildConfigFormatError, BuildConfigValidationError,
    BuildIntegrationError, BuildMonitorError, BuilderError, BuildConfigurationError,
    BuildExecutionError, BuildArtifactError,
    # Storage and data errors
    StorageManagerError, StorageError, StorageAdapterError, HistoricalDataError,
    HistoricalDataManagerError, DataRetrievalError, DataValidationError,
    DataFetchError, CacheError, ResultComparisonError, QueryError,
    # Analysis errors
    ChangeTrackingError, FunctionExtractionError, CrashAnalysisError, CoverageAnalysisError,
    # Benchmark errors
    BenchmarkError, BenchmarkValidationError, UnsupportedLanguageError,
    # Metadata errors
    MetadataError, MetadataParseError, MetadataValidationError,
    # Artifact errors
    ArtifactError, ArtifactNotFoundException, ArtifactNotFoundError,
    ArtifactValidationError, ArtifactStorageError, ArtifactIntegrityError,
    # Docker errors
    DockerManagerError, DockerExecutionError, DockerImageError, DockerContainerError,
    # File errors
    FileUtilsError, FilePermissionError, FileFormatError,
    WorkDirError, WorkDirPermissionError, WorkDirValidationError,
    # Repository errors
    RepositoryError, RepositoryNotInitializedError, CloneError, UpdateError,
    # Manager errors
    OSSFuzzManagerError,
    # General/legacy errors
    SDKError, ConnectionError,
    # Utility functions
    handle_error, format_error, to_dict
)

# Public API - All exports available to SDK clients
__all__ = [
    # Core SDK - Main classes according to UML diagram
    'OSSFuzzManager', 'BenchmarkManager', 'Benchmark',

    # Data models and enums
    'Severity', 'Sanitizer', 'Sanitizer', 'FuzzingEngine',

    # Core error types and enums
    'ErrorCode', 'ErrorDomain', 'OSSFuzzError',
    # Authentication errors
    'AuthenticationError', 'InvalidCredentialsError', 'TokenExpiredError',
    # Configuration errors
    'ConfigurationError', 'ConfigValidationError',
    # API errors
    'APIError',
    # Network errors
    'NetworkError', 'NetworkTimeoutError', 'StorageConnectionError',
    # Validation errors
    'ValidationError', 'InvalidParameterError', 'DataAggregationError', 'DataExportError',
    # Project errors
    'ProjectNotFoundError', 'ProjectInfoError',
    # Fuzzing errors
    'FuzzingError', 'FuzzRunnerError', 'FuzzExecutionError', 'RunConfigurationError',
    'ResultCollectionError', 'CloudRunnerError', 'CloudAuthError', 'CloudApiError', 'LocalRunnerError',
    # Rate limiting
    'RateLimitError',
    # Build errors
    'BuildSystemError', 'BuildSystemNotFoundError', 'BuildConfigError',
    'BuildConfigFileNotFoundError', 'BuildConfigFormatError', 'BuildConfigValidationError',
    'BuildIntegrationError', 'BuildMonitorError', 'BuilderError', 'BuildConfigurationError',
    'BuildExecutionError', 'BuildArtifactError',
    # Storage and data errors
    'StorageManagerError', 'StorageError', 'StorageAdapterError', 'HistoricalDataError',
    'HistoricalDataManagerError', 'DataRetrievalError', 'DataValidationError',
    'DataFetchError', 'CacheError', 'ResultComparisonError', 'QueryError',
    # Analysis errors
    'ChangeTrackingError', 'FunctionExtractionError', 'CrashAnalysisError', 'CoverageAnalysisError',
    # Benchmark errors
    'BenchmarkError', 'BenchmarkValidationError', 'UnsupportedLanguageError',
    # Metadata errors
    'MetadataError', 'MetadataParseError', 'MetadataValidationError',
    # Artifact errors
    'ArtifactError', 'ArtifactNotFoundException', 'ArtifactNotFoundError',
    'ArtifactValidationError', 'ArtifactStorageError', 'ArtifactIntegrityError',
    # Docker errors
    'DockerManagerError', 'DockerExecutionError', 'DockerImageError', 'DockerContainerError',
    # File errors
    'FileUtilsError', 'FilePermissionError', 'FileFormatError',
    'WorkDirError', 'WorkDirPermissionError', 'WorkDirValidationError',
    # Repository errors
    'RepositoryError', 'RepositoryNotInitializedError', 'CloneError', 'UpdateError',
    # Manager errors
    'OSSFuzzManagerError',
    # General/legacy errors
    'SDKError', 'ConnectionError',
    # Utility functions
    'handle_error', 'format_error', 'to_dict',
]
