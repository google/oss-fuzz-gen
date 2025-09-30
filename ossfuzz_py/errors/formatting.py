"""
Error formatting and conversion utilities for the OSS-Fuzz Python SDK.

This module provides centralized error formatting, conversion from standard
Python exceptions to SDK errors, and serialization utilities.
"""

from typing import Any, Dict, Type

from ossfuzz_py.errors.core import ErrorCode, ErrorDomain, OSSFuzzError
from ossfuzz_py.errors.factory import (ConfigurationError, FileFormatError,
                                       FilePermissionError, NetworkError,
                                       ValidationError)

# Mapping from Python built-in exceptions to SDK error classes
_CONVERSION_MAP: Dict[Type[Exception], Type[OSSFuzzError]] = {
    # Network-related exceptions
    ConnectionError: NetworkError,
    TimeoutError: NetworkError,
    OSError: NetworkError,

    # Validation and data exceptions
    ValueError: ValidationError,
    TypeError: ValidationError,

    # Configuration exceptions
    KeyError: ConfigurationError,
    AttributeError: ConfigurationError,

    # File system exceptions
    PermissionError: FilePermissionError,
    FileNotFoundError: FileFormatError,
    IsADirectoryError: FileFormatError,
    NotADirectoryError: FileFormatError,

    # Authentication exceptions (if any standard ones exist)
    # Note: Most auth errors will be custom, but we can catch some generic ones
}

def handle_error(exc: Exception) -> OSSFuzzError:
  """
  Convert various exceptions to OSS-Fuzz SDK errors using mapping.

  This function provides a centralized way to convert standard Python
  exceptions and third-party exceptions into structured SDK errors.

  Args:
      exc: The exception to convert

  Returns:
      OSSFuzzError: The converted SDK error

  Examples:
      >>> error = handle_error(ValueError("Invalid input"))
      >>> isinstance(error, ValidationError)
      True
      >>> error.code
      <ErrorCode.VALIDATION_FAILED: 'VALIDATION_FAILED'>
  """
  # If it's already an OSSFuzzError, return as-is
  if isinstance(exc, OSSFuzzError):
    return exc

  # Check for specific exception type mappings
  for py_exc_type, sdk_error_class in _CONVERSION_MAP.items():
    if isinstance(exc, py_exc_type):
      return sdk_error_class(str(exc))

  # Handle special cases with more context
  if isinstance(exc, KeyError):
    return ConfigurationError(f"Missing required key: {str(exc)}")

  # Default fallback
  return OSSFuzzError(str(exc), ErrorCode.UNKNOWN, ErrorDomain.CONFIG)

def to_dict(error: OSSFuzzError) -> Dict[str, Any]:
  """
  Convert an OSSFuzzError to dictionary format for serialization.

  Args:
      error: The error to convert

  Returns:
      Dictionary containing error information

  Examples:
      >>> error = OSSFuzzError("Test error", ErrorCode.VALIDATION_FAILED,
      ErrorDomain.VALIDATION)
      >>> result = to_dict(error)
      >>> result['message']
      'Test error'
      >>> result['code']
      'VALIDATION_FAILED'
  """
  return error.to_dict()

def format_error(error: OSSFuzzError) -> str:
  """
  Format an error for display with domain and code information.

  Args:
      error: The error to format

  Returns:
      Formatted error message string

  Examples:
      >>> error = OSSFuzzError("Test failed", ErrorCode.VALIDATION_FAILED,
      ErrorDomain.VALIDATION)
      >>> format_error(error)
      '[VALIDATION/VALIDATION_FAILED] Test failed'
  """
  base_message = f"[{error.domain.name}/{error.code.value}] {error.message}"

  if error.details:
    # Format details in a readable way
    details_str = ", ".join(
        f"{k}={v}" for k, v in error.details.items() if v is not None)
    if details_str:
      base_message += f" (Details: {details_str})"

  return base_message

def format_error_simple(error: OSSFuzzError) -> str:
  """
  Format an error for simple display (just message and code).

  Args:
      error: The error to format

  Returns:
      Simple formatted error message

  Examples:
      >>> error = OSSFuzzError("Test failed", ErrorCode.VALIDATION_FAILED,
      ErrorDomain.VALIDATION)
      >>> format_error_simple(error)
      'VALIDATION_FAILED: Test failed'
  """
  return f"{error.code.value}: {error.message}"

def format_error_json(error: OSSFuzzError) -> str:
  """
  Format an error as JSON string for logging or API responses.

  Args:
      error: The error to format

  Returns:
      JSON string representation of the error
  """
  import json
  return json.dumps(to_dict(error), indent=2)

def is_retryable_error(error: Exception) -> bool:
  """
  Determine if an error (SDK or standard) represents a retryable condition.

  Args:
      error: The error to check

  Returns:
      True if the error condition might be temporary and worth retrying

  Examples:
      >>> is_retryable_error(ConnectionError("Network timeout"))
      True
      >>> is_retryable_error(ValueError("Invalid input"))
      False
  """
  # Convert to SDK error first if needed
  if not isinstance(error, OSSFuzzError):
    error = handle_error(error)

  return error.retryable()

def get_error_category(error: Exception) -> str:
  """
  Get the high-level category of an error.

  Args:
      error: The error to categorize

  Returns:
      String representing the error category

  Examples:
      >>> get_error_category(ValueError("test"))
      'VALIDATION'
      >>> get_error_category(ConnectionError("network"))
      'NET'
  """
  # Convert to SDK error first if needed
  if not isinstance(error, OSSFuzzError):
    error = handle_error(error)

  return error.domain.name

# Backward compatibility functions (matching original API)
def format_error_legacy(error: OSSFuzzError) -> str:
  """
  Legacy format function for backward compatibility.

  This matches the original format_error function signature and behavior.
  """
  message = f"{error.code.value}: {str(error)}"
  if error.details:
    message += f"\nDetails: {error.details}"
  return message
