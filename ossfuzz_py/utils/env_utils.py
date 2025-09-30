"""
Centralized environment variable access utilities for the OSS-Fuzz SDK.

This module provides type-safe, centralized access to environment variables
with support for defaults, validation, and type conversion.
"""

import os
from typing import Dict, Optional

from ossfuzz_py.errors import EnvironmentParametersError
from ossfuzz_py.utils.env_vars import EnvVars

class EnvUtils:
  """
  Centralized environment variable utilities for the OSS-Fuzz SDK.

  This class provides type-safe, centralized access to environment variables
  with support for defaults, validation, and type conversion.
  """

  @staticmethod
  def get_env(var: EnvVars,
              default: Optional[str] = None,
              required: bool = False) -> Optional[str]:
    """
    Get an environment variable value with type safety and validation.

    Args: var: The environment variable to retrieve (from EnvVars enum)
    default: Default value if the environment variable is not set required:
    If True, raises EnvironmentParametersError if the variable is not set

    Returns:
      The environment variable value, default value, or None

    Raises:
      EnvironmentParametersError: If required=True and the variable is
      not set

    Examples:
        >>> from ossfuzz_py.utils.env_utils import EnvUtils
        >>> from ossfuzz_py.utils.env_vars import EnvVars
        >>>
        >>> # Get with default
        >>> oss_fuzz_dir = EnvUtils.get_env(
        EnvVars.OSS_FUZZ_DIR, '/tmp/oss-fuzz')
        >>>
        >>> # Get required variable
        >>> creds = EnvUtils.get_env(
        EnvVars.GOOGLE_APPLICATION_CREDENTIALS, required=True)
    """
    value = os.getenv(var.value, default)
    if required and value is None:
      raise EnvironmentParametersError(
          f"Missing required environment variable: {var.value}")
    return value

  @staticmethod
  def get_env_bool(var: EnvVars,
                   default: bool = False,
                   required: bool = False) -> bool:
    """
    Get an environment variable as a boolean value.

    Treats the following values as True (case-insensitive):
    - "1", "true", "yes", "on"

    All other values are treated as False.

    Args:
        var: The environment variable to retrieve
        default: Default value if the environment variable is not set
        required: If True, raises EnvironmentParametersError
        if the variable is not set

    Returns:
        Boolean value of the environment variable

    Raises:
        EnvironmentParametersError: If required=True and the variable is not set
    """
    value = EnvUtils.get_env(var, required=required)
    if value is None:
      return default

    return value.lower() in ('1', 'true', 'yes', 'on')

  @staticmethod
  def get_env_int(var: EnvVars,
                  default: Optional[int] = None,
                  required: bool = False) -> Optional[int]:
    """
    Get an environment variable as an integer value.

    Args:
        var: The environment variable to retrieve
        default: Default value if the environment variable is not set
        required: If True, raises EnvironmentParametersError
        if the variable is not set

    Returns:
        Integer value of the environment variable

    Raises:
        EnvironmentParametersError: If required=True and the variable is not set
        ValueError: If the environment variable value cannot be converted to int
    """
    value = EnvUtils.get_env(var, required=required)
    if value is None:
      return default

    try:
      return int(value)
    except ValueError:
      raise ValueError(
          f"Environment variable {var.value} has invalid integer value: {value}"
      )

  @staticmethod
  def get_env_dict(prefix: str) -> Dict[str, str]:
    """
    Get all environment variables with a specific prefix.

    Args:
        prefix: The prefix to filter environment variables (e.g., 'OSSFUZZ_')

    Returns:
        Dictionary of environment variables with the prefix removed from keys

    Examples:
        >>> # Get all OSSFUZZ_ prefixed variables
        >>> config = EnvUtils.get_env_dict('OSSFUZZ_')
        >>> # Returns: {'LOG_LEVEL': 'INFO', 'API_BASE_URL': 'https://...'}
    """
    result = {}
    for key, value in os.environ.items():
      if key.startswith(prefix):
        # Remove prefix from key
        clean_key = key[len(prefix):]
        result[clean_key] = value
    return result

  @staticmethod
  def is_ci_environment() -> bool:
    """
    Check if the current environment is a CI/CD environment.

    Returns:
        True if running in CI/CD, False otherwise
    """
    return EnvUtils.get_env_bool(EnvVars.CI) or EnvUtils.get_env_bool(
        EnvVars.GITHUB_ACTIONS)

  @staticmethod
  def get_oss_fuzz_dir() -> str:
    """
    Get the OSS-Fuzz directory path with a sensible default.

    Returns:
        Path to the OSS-Fuzz directory
    """
    result = EnvUtils.get_env(EnvVars.OSS_FUZZ_DIR, '/tmp/oss-fuzz')
    return result or '/tmp/oss-fuzz'

  @staticmethod
  def get_venv_dir() -> str:
    """
    Get the virtual environment directory path with a sensible default.

    Returns:
        Path to the virtual environment directory
    """
    result = EnvUtils.get_env(EnvVars.VENV_DIR, './venv')
    return result or './venv'

  @staticmethod
  def get_work_dir() -> str:
    """
    Get the work directory path with a sensible default.

    Returns:
        Path to the work directory
    """
    result = EnvUtils.get_env(EnvVars.WORK_DIR, '/tmp/ossfuzz_work')
    return result or '/tmp/ossfuzz_work'

  @staticmethod
  def has_gcp_credentials() -> bool:
    """
    Check if Google Cloud Platform credentials are configured.

    Returns:
        True if GCP credentials are available, False otherwise
    """
    return EnvUtils.get_env(EnvVars.GOOGLE_APPLICATION_CREDENTIALS) is not None

  @staticmethod
  def validate_required_env_vars(required_vars: list[EnvVars]) -> None:
    """
    Validate that all required environment variables are set.

    Args:
        required_vars: List of environment variables that must be set

    Raises:
        EnvironmentParametersError: If any required variable is missing
    """
    missing_vars = []
    for var in required_vars:
      if EnvUtils.get_env(var) is None:
        missing_vars.append(var.value)

    if missing_vars:
      raise EnvironmentParametersError(
          f"Missing required environment variables: {', '.join(missing_vars)}")
