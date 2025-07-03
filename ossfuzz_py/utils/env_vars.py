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
Centralized environment variable definitions for the OSS-Fuzz SDK.

This module provides a single source of truth for all environment variables
used throughout the codebase, preventing typos and making it easier to
maintain and audit environment configuration.
"""

from enum import Enum


class EnvVars(str, Enum):
  """
  Enumeration of all environment variables used in the OSS-Fuzz SDK.

  This enum inherits from str to allow direct string comparison and usage
  while providing IDE autocompletion and type safety.
  """

  # Google Cloud Platform credentials and configuration
  GOOGLE_APPLICATION_CREDENTIALS = "GOOGLE_APPLICATION_CREDENTIALS"

  # OSS-Fuzz specific directories and paths
  OSS_FUZZ_DIR = "OSS_FUZZ_DIR"
  VENV_DIR = "VENV_DIR"
  WORK_DIR = "WORK_DIR"
  GOOGLE_CLOUD_PROJECT = "GOOGLE_CLOUD_PROJECT"

  # OSS-Fuzz Generator (OFG) specific settings
  OFG_USE_CACHING = "OFG_USE_CACHING"
  OFG_CLEAN_UP_OSS_FUZZ = "OFG_CLEAN_UP_OSS_FUZZ"

  # CI/CD environment detection
  CI = "CI"
  GITHUB_ACTIONS = "GITHUB_ACTIONS"

  # OSS-Fuzz SDK configuration (with OSSFUZZ_ prefix)
  OSSFUZZ_LOG_LEVEL = "OSSFUZZ_LOG_LEVEL"
  OSSFUZZ_API_BASE_URL = "OSSFUZZ_API_BASE_URL"
  OSSFUZZ_AUTH_METHOD = "OSSFUZZ_AUTH_METHOD"
  OSSFUZZ_TIMEOUT = "OSSFUZZ_TIMEOUT"
  OSSFUZZ_MAX_RETRIES = "OSSFUZZ_MAX_RETRIES"

  # Additional OSSFUZZ_ prefixed variables that might be used
  OSSFUZZ_CLIENT_ID = "OSSFUZZ_CLIENT_ID"
  OSSFUZZ_CLIENT_SECRET = "OSSFUZZ_CLIENT_SECRET"
  OSSFUZZ_TOKEN_URL = "OSSFUZZ_TOKEN_URL"
  OSSFUZZ_API_KEY = "OSSFUZZ_API_KEY"
