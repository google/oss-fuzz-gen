"""
Dynamic error subclass factory and registry for the OSS-Fuzz Python SDK.

This module provides a factory system for generating thin error subclasses
and maintaining a registry of all error types.
"""

from typing import Dict, Optional, Type

from ossfuzz_py.errors.core import (ErrorCode, ErrorDetails, ErrorDomain,
                                    OSSFuzzError)

# Global registry of all generated error classes
_ERROR_REGISTRY: Dict[str, Type[OSSFuzzError]] = {}

def make_error(name: str,
               code: ErrorCode,
               domain: ErrorDomain,
               default_message: Optional[str] = None) -> Type[OSSFuzzError]:
  """
  Create a new error subclass with specified code and domain.

  Args:
      name: Name of the error class
      code: Default error code for this class
      domain: Error domain for this class
      default_message: Optional default message

  Returns:
      New error class type
  """

  def _init(self, message: str = '', details: Optional[ErrorDetails] = None):
    """Initialize the error with message and details."""
    final_message = message or default_message or f"{name} occurred"
    # pylint: disable=unnecessary-dunder-call
    OSSFuzzError.__init__(self, final_message, code, domain, details)

  # Create the new class
  cls = type(
      name,
      (OSSFuzzError,),
      {
          "__init__": _init,
          "__module__": __name__,
          "__doc__": f"Raised when "
                     f"{name.lower().replace('error', '')} errors occur.",
      },
  )

  # Register the class
  _ERROR_REGISTRY[name] = cls
  return cls

def get_error_class(name: str) -> Optional[Type[OSSFuzzError]]:
  """
  Get an error class by name from the registry.

  Args:
      name: Name of the error class

  Returns:
      Error class if found, None otherwise
  """
  return _ERROR_REGISTRY.get(name)

def list_error_classes() -> Dict[str, Type[OSSFuzzError]]:
  """
  Get all registered error classes.

  Returns:
      Dictionary mapping class names to class types
  """
  return _ERROR_REGISTRY.copy()

# Generate all required error subclasses
# Authentication errors
AuthenticationError = make_error("AuthenticationError",
                                 ErrorCode.AUTHENTICATION_FAILED,
                                 ErrorDomain.AUTH)
InvalidCredentialsError = make_error("InvalidCredentialsError",
                                     ErrorCode.INVALID_CREDENTIALS,
                                     ErrorDomain.AUTH,
                                     "Invalid credentials provided")
TokenExpiredError = make_error("TokenExpiredError", ErrorCode.TOKEN_EXPIRED,
                               ErrorDomain.AUTH,
                               "Authentication token has expired")

# Configuration errors
ConfigurationError = make_error("ConfigurationError", ErrorCode.INVALID_CONFIG,
                                ErrorDomain.CONFIG)
ConfigValidationError = make_error("ConfigValidationError",
                                   ErrorCode.CONFIG_VALIDATION_FAILED,
                                   ErrorDomain.CONFIG)

# API errors
APIError = make_error("APIError", ErrorCode.API_ERROR, ErrorDomain.API)

# Network errors
NetworkError = make_error("NetworkError", ErrorCode.NETWORK_ERROR,
                          ErrorDomain.NET)
NetworkTimeoutError = make_error("NetworkTimeoutError",
                                 ErrorCode.CONNECTION_TIMEOUT, ErrorDomain.NET)
StorageConnectionError = make_error("StorageConnectionError",
                                    ErrorCode.STORAGE_CONNECTION_ERROR,
                                    ErrorDomain.NET)

# Validation errors
ValidationError = make_error("ValidationError", ErrorCode.VALIDATION_FAILED,
                             ErrorDomain.VALIDATION)
InvalidParameterError = make_error("InvalidParameterError",
                                   ErrorCode.INVALID_PARAMETER,
                                   ErrorDomain.VALIDATION)
DataAggregationError = make_error("DataAggregationError",
                                  ErrorCode.DATA_AGGREGATION_ERROR,
                                  ErrorDomain.VALIDATION)
DataExportError = make_error("DataExportError", ErrorCode.DATA_EXPORT_ERROR,
                             ErrorDomain.VALIDATION)

# Project errors
ProjectNotFoundError = make_error("ProjectNotFoundError",
                                  ErrorCode.PROJECT_NOT_FOUND,
                                  ErrorDomain.PROJECT)
ProjectInfoError = make_error("ProjectInfoError", ErrorCode.PROJECT_INFO_ERROR,
                              ErrorDomain.PROJECT)

# Fuzzing errors
FuzzingError = make_error("FuzzingError", ErrorCode.FUZZING_FAILED,
                          ErrorDomain.FUZZ)
FuzzRunnerError = make_error("FuzzRunnerError", ErrorCode.FUZZ_EXECUTION_ERROR,
                             ErrorDomain.FUZZ)
FuzzExecutionError = make_error("FuzzExecutionError",
                                ErrorCode.FUZZ_EXECUTION_ERROR,
                                ErrorDomain.FUZZ)
RunConfigurationError = make_error("RunConfigurationError",
                                   ErrorCode.RUN_CONFIGURATION_ERROR,
                                   ErrorDomain.FUZZ)
ResultCollectionError = make_error("ResultCollectionError",
                                   ErrorCode.RESULT_COLLECTION_ERROR,
                                   ErrorDomain.FUZZ)
CloudRunnerError = make_error("CloudRunnerError",
                              ErrorCode.FUZZ_EXECUTION_ERROR, ErrorDomain.FUZZ)
CloudAuthError = make_error("CloudAuthError", ErrorCode.CLOUD_AUTH_ERROR,
                            ErrorDomain.FUZZ)
CloudApiError = make_error("CloudApiError", ErrorCode.CLOUD_API_ERROR,
                           ErrorDomain.FUZZ)
LocalRunnerError = make_error("LocalRunnerError",
                              ErrorCode.FUZZ_EXECUTION_ERROR, ErrorDomain.FUZZ)

# Rate limiting
RateLimitError = make_error("RateLimitError", ErrorCode.RATE_LIMIT_EXCEEDED,
                            ErrorDomain.NET)

# Build errors
BuildSystemError = make_error("BuildSystemError", ErrorCode.BUILD_FAILED,
                              ErrorDomain.BUILD)
BuildSystemNotFoundError = make_error("BuildSystemNotFoundError",
                                      ErrorCode.BUILD_SYSTEM_NOT_FOUND,
                                      ErrorDomain.BUILD)
BuildConfigError = make_error("BuildConfigError", ErrorCode.BUILD_CONFIG_ERROR,
                              ErrorDomain.BUILD)
BuildConfigFileNotFoundError = make_error("BuildConfigFileNotFoundError",
                                          ErrorCode.BUILD_CONFIG_FILE_NOT_FOUND,
                                          ErrorDomain.BUILD)
BuildConfigFormatError = make_error("BuildConfigFormatError",
                                    ErrorCode.BUILD_CONFIG_FORMAT_ERROR,
                                    ErrorDomain.BUILD)
BuildConfigValidationError = make_error("BuildConfigValidationError",
                                        ErrorCode.BUILD_CONFIG_VALIDATION_ERROR,
                                        ErrorDomain.BUILD)
BuildIntegrationError = make_error("BuildIntegrationError",
                                   ErrorCode.BUILD_INTEGRATION_ERROR,
                                   ErrorDomain.BUILD)
BuildMonitorError = make_error("BuildMonitorError",
                               ErrorCode.BUILD_MONITOR_ERROR, ErrorDomain.BUILD)
BuilderError = make_error("BuilderError", ErrorCode.BUILD_FAILED,
                          ErrorDomain.BUILD)
CloudBuildError = make_error("CloudBuildError", ErrorCode.CLOUD_BUILD_FAILED,
                             ErrorDomain.BUILD)
BuildConfigurationError = make_error("BuildConfigurationError",
                                     ErrorCode.BUILD_CONFIG_ERROR,
                                     ErrorDomain.BUILD)
BuildExecutionError = make_error("BuildExecutionError",
                                 ErrorCode.BUILD_EXECUTION_ERROR,
                                 ErrorDomain.BUILD)
BuildArtifactError = make_error("BuildArtifactError",
                                ErrorCode.BUILD_ARTIFACT_ERROR,
                                ErrorDomain.BUILD)

# Storage and data errors
StorageManagerError = make_error("StorageManagerError", ErrorCode.STORAGE_ERROR,
                                 ErrorDomain.STORAGE)
StorageError = make_error("StorageError", ErrorCode.STORAGE_ERROR,
                          ErrorDomain.STORAGE)
StorageAdapterError = make_error("StorageAdapterError", ErrorCode.STORAGE_ERROR,
                                 ErrorDomain.STORAGE)
HistoricalDataError = make_error("HistoricalDataError", ErrorCode.DATA_ERROR,
                                 ErrorDomain.DATA)
HistoricalDataManagerError = make_error("HistoricalDataManagerError",
                                        ErrorCode.DATA_ERROR, ErrorDomain.DATA)
DataRetrievalError = make_error("DataRetrievalError",
                                ErrorCode.DATA_RETRIEVAL_ERROR,
                                ErrorDomain.DATA)
DataValidationError = make_error("DataValidationError",
                                 ErrorCode.DATA_VALIDATION_ERROR,
                                 ErrorDomain.DATA)
DataFetchError = make_error("DataFetchError", ErrorCode.DATA_FETCH_ERROR,
                            ErrorDomain.DATA)
CacheError = make_error("CacheError", ErrorCode.CACHE_ERROR, ErrorDomain.DATA)
ResultComparisonError = make_error("ResultComparisonError",
                                   ErrorCode.RESULT_COMPARISON_ERROR,
                                   ErrorDomain.DATA)
QueryError = make_error("QueryError", ErrorCode.QUERY_ERROR, ErrorDomain.DATA)
EnvironmentParametersError = make_error("EnvironmentParametersError",
                                        ErrorCode.ENVIRONMENT_PARAMETERS_ERROR,
                                        ErrorDomain.VALIDATION)

# Analysis errors
ChangeTrackingError = make_error("ChangeTrackingError",
                                 ErrorCode.CHANGE_TRACKING_ERROR,
                                 ErrorDomain.ANALYSIS)
FunctionExtractionError = make_error("FunctionExtractionError",
                                     ErrorCode.FUNCTION_EXTRACTION_ERROR,
                                     ErrorDomain.ANALYSIS)
CrashAnalysisError = make_error("CrashAnalysisError",
                                ErrorCode.CRASH_ANALYSIS_ERROR,
                                ErrorDomain.ANALYSIS)
CoverageAnalysisError = make_error("CoverageAnalysisError",
                                   ErrorCode.COVERAGE_ANALYSIS_ERROR,
                                   ErrorDomain.COVERAGE)

# Benchmark errors
BenchmarkError = make_error("BenchmarkError", ErrorCode.BENCHMARK_ERROR,
                            ErrorDomain.BENCHMARK)
BenchmarkValidationError = make_error("BenchmarkValidationError",
                                      ErrorCode.BENCHMARK_VALIDATION_ERROR,
                                      ErrorDomain.BENCHMARK)
UnsupportedLanguageError = make_error("UnsupportedLanguageError",
                                      ErrorCode.UNSUPPORTED_LANGUAGE,
                                      ErrorDomain.BENCHMARK)

# Metadata errors
MetadataError = make_error("MetadataError", ErrorCode.METADATA_ERROR,
                           ErrorDomain.METADATA)
MetadataParseError = make_error("MetadataParseError",
                                ErrorCode.METADATA_PARSE_ERROR,
                                ErrorDomain.METADATA)
MetadataValidationError = make_error("MetadataValidationError",
                                     ErrorCode.METADATA_VALIDATION_ERROR,
                                     ErrorDomain.METADATA)

# Artifact errors
ArtifactError = make_error("ArtifactError", ErrorCode.ARTIFACT_ERROR,
                           ErrorDomain.ARTIFACT)
ArtifactNotFoundException = make_error("ArtifactNotFoundException",
                                       ErrorCode.ARTIFACT_NOT_FOUND,
                                       ErrorDomain.ARTIFACT)
ArtifactNotFoundError = make_error("ArtifactNotFoundError",
                                   ErrorCode.ARTIFACT_NOT_FOUND,
                                   ErrorDomain.ARTIFACT)
ArtifactValidationError = make_error("ArtifactValidationError",
                                     ErrorCode.ARTIFACT_VALIDATION_ERROR,
                                     ErrorDomain.ARTIFACT)
ArtifactStorageError = make_error("ArtifactStorageError",
                                  ErrorCode.ARTIFACT_STORAGE_ERROR,
                                  ErrorDomain.ARTIFACT)
ArtifactIntegrityError = make_error("ArtifactIntegrityError",
                                    ErrorCode.ARTIFACT_INTEGRITY_ERROR,
                                    ErrorDomain.ARTIFACT)

# Docker errors
DockerManagerError = make_error("DockerManagerError", ErrorCode.DOCKER_ERROR,
                                ErrorDomain.DOCKER)
DockerExecutionError = make_error("DockerExecutionError",
                                  ErrorCode.DOCKER_EXECUTION_ERROR,
                                  ErrorDomain.DOCKER)
DockerImageError = make_error("DockerImageError", ErrorCode.DOCKER_IMAGE_ERROR,
                              ErrorDomain.DOCKER)
DockerContainerError = make_error("DockerContainerError",
                                  ErrorCode.DOCKER_CONTAINER_ERROR,
                                  ErrorDomain.DOCKER)

# File errors
FileUtilsError = make_error("FileUtilsError", ErrorCode.FILE_ERROR,
                            ErrorDomain.FILE)
FilePermissionError = make_error("FilePermissionError",
                                 ErrorCode.FILE_PERMISSION_ERROR,
                                 ErrorDomain.FILE)
FileFormatError = make_error("FileFormatError", ErrorCode.FILE_FORMAT_ERROR,
                             ErrorDomain.FILE)
WorkDirError = make_error("WorkDirError", ErrorCode.WORK_DIR_ERROR,
                          ErrorDomain.FILE)
WorkDirPermissionError = make_error("WorkDirPermissionError",
                                    ErrorCode.WORK_DIR_PERMISSION_ERROR,
                                    ErrorDomain.FILE)
WorkDirValidationError = make_error("WorkDirValidationError",
                                    ErrorCode.WORK_DIR_VALIDATION_ERROR,
                                    ErrorDomain.FILE)

# Repository errors
RepositoryError = make_error("RepositoryError", ErrorCode.REPOSITORY_ERROR,
                             ErrorDomain.REPOSITORY)
RepositoryNotInitializedError = make_error("RepositoryNotInitializedError",
                                           ErrorCode.REPOSITORY_NOT_INITIALIZED,
                                           ErrorDomain.REPOSITORY)
CloneError = make_error("CloneError", ErrorCode.CLONE_ERROR,
                        ErrorDomain.REPOSITORY)
UpdateError = make_error("UpdateError", ErrorCode.UPDATE_ERROR,
                         ErrorDomain.REPOSITORY)

# Manager errors
OSSFuzzManagerError = make_error("OSSFuzzManagerError",
                                 ErrorCode.INVALID_CONFIG, ErrorDomain.CONFIG)

# General/legacy errors for backward compatibility
SDKError = make_error("SDKError", ErrorCode.UNKNOWN, ErrorDomain.CONFIG)
