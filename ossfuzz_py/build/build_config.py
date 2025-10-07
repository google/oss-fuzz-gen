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
Build a configuration system for the Custom Fuzzing Module.

This module provides a flexible configuration system for defining and
validating build parameters across different build environments. It ensures
proper validation of build configurations while abstracting the underlying
OSS-Fuzz build system complexities.

The configuration system is designed to be: 1. Flexible - supporting various
build environments and parameters 2. Validated - ensuring all required
parameters are present and correctly formatted 3. Extensible - allowing for
custom configuration options for specific build needs

For more details on how this fits into the overall architecture, see the
builder_uml.jpg diagram.
"""

import logging
from typing import Any, Dict, List, Optional

from ossfuzz_py.core.data_models import FuzzingEngine, ProjectConfig, Sanitizer
from ossfuzz_py.errors import BuildConfigError

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.build_config')


class BuildConfig:
  """
  Build configuration class that matches the UML specification.

  This class encapsulates all parameters needed for building fuzz targets,
  following the structure defined in the UML diagram.
  """

  def __init__(self,
               project_name: str,
               language: str,
               sanitizer: Sanitizer,
               architecture: str = "x86_64",
               fuzzing_engine: FuzzingEngine = FuzzingEngine.LIBFUZZER,
               environment_vars: Optional[Dict[str, str]] = None,
               build_args: Optional[List[str]] = None):
    """
    Initialize the build configuration.

    Args:
        project_name: Name of the project
        language: Programming language of the project
        sanitizer: Sanitizer to use
        architecture: Target architecture (default: x86_64)
        fuzzing_engine: Fuzzing engine to use (default: libfuzzer)
        environment_vars: Environment variables for the build
        build_args: Build arguments
    """
    self.project_name = project_name
    self.language = language
    self.sanitizer = sanitizer
    self.architecture = architecture
    self.fuzzing_engine = fuzzing_engine
    self.environment_vars = environment_vars or {}
    self.build_args = build_args or []
    self.logger = logger

    self.logger.debug("Initialized BuildConfig for project %s", project_name)

  @classmethod
  def from_project_config(cls, project_config: ProjectConfig) -> 'BuildConfig':
    """
    Create a BuildConfig from a ProjectConfig.

    Args:
        project_config: ProjectConfig instance

    Returns:
        BuildConfig: New BuildConfig instance
    """
    return cls(project_name=project_config.project_name,
               language=project_config.language,
               sanitizer=project_config.sanitizer,
               architecture=project_config.architecture,
               fuzzing_engine=project_config.fuzzing_engine,
               environment_vars=project_config.environment_vars,
               build_args=project_config.build_args)

  def validate(self) -> None:
    """
    Validate the build configuration.

    Raises:
        BuildConfigError: If validation fails
    """
    if not self.project_name:
      raise BuildConfigError("project_name is required")

    if not self.language:
      raise BuildConfigError("language is required")

    if not isinstance(self.sanitizer, Sanitizer):
      raise BuildConfigError("sanitizer must be a Sanitizer enum value")

    if not isinstance(self.fuzzing_engine, FuzzingEngine):
      raise BuildConfigError(
          "fuzzing_engine must be a FuzzingEngine enum value")

    self.logger.debug("BuildConfig validation passed")

  def to_dict(self) -> Dict[str, Any]:
    """
    Convert the configuration to a dictionary.

    Returns:
        Dictionary representation of the configuration
    """
    return {
        'project_name': self.project_name,
        'language': self.language,
        'sanitizer': self.sanitizer.value,
        'architecture': self.architecture,
        'fuzzing_engine': self.fuzzing_engine.value,
        'environment_vars': self.environment_vars,
        'build_args': self.build_args
    }
