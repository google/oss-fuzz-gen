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
from .core import (
    ErrorDomain,
    ErrorCode, 
    ErrorDetails,
    OSSFuzzError
)

# All generated error classes from factory
from .factory import (
    # Authentication errors
    AuthenticationError,
    InvalidCredentialsError,
    TokenExpiredError,
    
    # Configuration errors
    ConfigurationError,
    ConfigValidationError,
    
    # API errors
    APIError,
    
    # Network errors
    NetworkError,
    NetworkTimeoutError,
    StorageConnectionError,
    
    # Validation errors
    ValidationError,
    InvalidParameterError,
    DataAggregationError,
    DataExportError,
    
    # Project errors
    ProjectNotFoundError,
    ProjectInfoError,
    
    # Fuzzing errors
    FuzzingError,
    FuzzRunnerError,
    FuzzExecutionError,
    RunConfigurationError,
    ResultCollectionError,
    CloudRunnerError,
    CloudAuthError,
    CloudApiError,
    LocalRunnerError,
    
    # Rate limiting
    RateLimitError,
    
    # Build errors
    BuildSystemError,
    BuildSystemNotFoundError,
    BuildConfigError,
    BuildConfigFileNotFoundError,
    BuildConfigFormatError,
    BuildConfigValidationError,
    BuildIntegrationError,
    BuildMonitorError,
    BuilderError,
    BuildConfigurationError,
    BuildExecutionError,
    BuildArtifactError,
    
    # Storage and data errors
    StorageManagerError,
    StorageError,
    StorageAdapterError,
    HistoricalDataError,
    HistoricalDataManagerError,
    DataRetrievalError,
    DataValidationError,
    DataFetchError,
    CacheError,
    ResultComparisonError,
    QueryError,
    
    # Analysis errors
    ChangeTrackingError,
    FunctionExtractionError,
    CrashAnalysisError,
    CoverageAnalysisError,
    
    # Benchmark errors
    BenchmarkError,
    BenchmarkValidationError,
    UnsupportedLanguageError,
    
    # Metadata errors
    MetadataError,
    MetadataParseError,
    MetadataValidationError,
    
    # Artifact errors
    ArtifactError,
    ArtifactNotFoundException,
    ArtifactNotFoundError,
    ArtifactValidationError,
    ArtifactStorageError,
    ArtifactIntegrityError,
    
    # Docker errors
    DockerManagerError,
    DockerExecutionError,
    DockerImageError,
    DockerContainerError,
    
    # File errors
    FileUtilsError,
    FilePermissionError,
    FileFormatError,
    WorkDirError,
    WorkDirPermissionError,
    WorkDirValidationError,
    
    # Repository errors
    RepositoryError,
    RepositoryNotInitializedError,
    CloneError,
    UpdateError,
    
    # Manager errors
    OSSFuzzManagerError,
    
    # General/legacy errors
    SDKError,
    ConnectionError,
    
    # Factory utilities
    make_error,
    get_error_class,
    list_error_classes,
)

# Formatting and conversion utilities
from .formatting import (
    handle_error,
    to_dict,
    format_error,
    format_error_simple,
    format_error_json,
    format_error_legacy,
    is_retryable_error,
    get_error_category,
    add_error_context,
)

# Backward compatibility aliases
# The original errors.py had these function names
format_error_original = format_error_legacy  # Original format_error behavior

# All public symbols for __all__
__all__ = [
    # Core types and enums
    'ErrorDomain',
    'ErrorCode',
    'ErrorDetails', 
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
    'ConnectionError',
    
    # Utility functions
    'handle_error',
    'to_dict',
    'format_error',
    'format_error_simple',
    'format_error_json',
    'is_retryable_error',
    'get_error_category',
    'add_error_context',
    
    # Factory utilities
    'make_error',
    'get_error_class',
    'list_error_classes',
]
