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
Abstract builder interface for the Custom Fuzzing Module build system.

This module defines the abstract Builder interface and implementations for
building fuzz targets in various environments (local, cloud). It provides a
clean abstraction over the complexities of OSS-Fuzz build processes while
maintaining loose coupling with the upstream OSS-Fuzz implementation.

The architecture follows the design described in the builder_uml.jpg diagram:
- Builder (abstract): Defines the interface for all builder implementations -
LocalBuilder: Concrete implementation for local build environments -
CloudBuilder: Concrete implementation for cloud/CI environments - Docker
integration via the DockerManager

For usage examples, see the jupyter notebooks in the examples directory.
"""
import logging
import os
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ossfuzz_py.build.build_config import BuildConfig
from ossfuzz_py.build.cloud_build_manager import CloudBuildManager
from ossfuzz_py.build.docker_manager import CommandResult, DockerManager
from ossfuzz_py.core.data_models import Sanitizer
from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.execution.fuzz_target import FuzzTarget
from ossfuzz_py.utils.file_utils import FileUtils

# NOTE: Running-related constants have been moved to LocalRunner and CloudRunner
# This module focuses only on building logic

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.builder')


class Result:
  """Simple result class for build operations."""

  def __init__(self,
               success: bool,
               message: str = "",
               artifacts: Optional[Dict[str, Path]] = None,
               metadata: Optional[Dict[str, Any]] = None):
    self.success = success
    self.message = message
    self.artifacts = artifacts or {}
    self.metadata = metadata or {}


class Builder(ABC):
  """
  Abstract base class for all builder implementations according to UML
  specification.

  This class defines the interface for build operations regardless of the
  underlying build environment. Concrete implementations handle the specifics
  of different build environments while maintaining a consistent interface.
  """

  def __init__(self, storage_manager: StorageManager,
               build_config: BuildConfig):
    """
    Initialize the builder.

    Args:
        storage_manager: Storage manager for artifacts and data
        build_config: Build configuration
    """
    self.storage_manager = storage_manager
    self.build_config = build_config
    self.logger = logger

    self.logger.debug("Initialized %s for project %s", self.__class__.__name__,
                      build_config.project_name)

  @abstractmethod
  def setup_environment(self) -> bool:
    """
    Set up the build environment.

    Returns:
        bool: True if setup was successful
    """

  @abstractmethod
  def build(self, target: FuzzTarget, sanitizer: Sanitizer) -> 'Result':
    """
    Build a fuzz target with the specified sanitizer.

    Args:
        target: The fuzz target to build
        sanitizer: The sanitizer to use

    Returns:
        Result: Build result object
    """

  @abstractmethod
  def clean(self) -> bool:
    """
    Clean up build artifacts and temporary files.

    Returns:
        bool: True if cleanup was successful
    """

  @abstractmethod
  def get_build_artifacts(self) -> Dict[str, Path]:
    """
    Get build artifacts.

    Returns:
        Dict[str, Path]: Dictionary mapping artifact names to paths
    """

  @abstractmethod
  def prepare_build_environment(self) -> bool:
    """
    Prepare the build environment (protected method).

    Returns:
        bool: True if preparation was successful
    """

  @abstractmethod
  def execute_build_command(self, command: List[str]) -> CommandResult:
    """
    Execute a build command (protected method).

    Args:
        command: Command to execute

    Returns:
        CommandResult: Result of command execution
    """

  @abstractmethod
  def process_build_artifacts(self) -> Dict[str, Path]:
    """
    Process build artifacts (protected method).

    Returns:
        Dict[str, Path]: Dictionary mapping artifact names to paths
    """


class LocalBuilder(Builder):
  """
  Local builder implementation that uses Docker for building fuzz targets.

  This class handles building fuzz targets in the local environment using
  Docker, following the UML specification.
  """

  def __init__(self, storage_manager: StorageManager, build_config: BuildConfig,
               docker_manager: DockerManager):
    """
    Initialize the local builder.

    Args:
        storage_manager: Storage manager for artifacts
        build_config: Build configuration
        docker_manager: Docker manager for container operations
    """
    super().__init__(storage_manager, build_config)
    self.docker_manager = docker_manager
    self._artifacts: Dict[str, Path] = {}

    self.logger.debug("Initialized LocalBuilder with Docker manager")

  def setup_environment(self) -> bool:
    """Set up the build environment."""
    try:
      # Prepare the project image
      image_name = self.docker_manager.prepare_project_image(
          self.build_config.project_name)
      self.logger.info("Environment setup complete with image: %s", image_name)
      return True
    except Exception as e:
      self.logger.error("Failed to setup environment: %s", e)
      return False

  def build(self,
            target: FuzzTarget,
            sanitizer: Sanitizer = Sanitizer.ADDRESS) -> Result:
    """Build a fuzz target with the specified sanitizer."""
    try:
      self.logger.info("Building target %s with sanitizer %s", target.name,
                       sanitizer.value)

      # Prepare build environment
      if not self.prepare_build_environment():
        return Result(False, "Failed to prepare build environment")

      # Use the build_local method (focused only on building)
      success, build_metadata = self.build_local(
          source_code=target.source_code,
          benchmark_target_name=target.name,
          sanitizer=sanitizer.value)

      if not success:
        error_msg = build_metadata.get('error', 'Local build failed')
        return Result(False, error_msg)

      # # Store artifacts in storage manager
      # for name, path in artifacts.items():
      #     if path.exists():
      #         with open(path, 'rb') as f:
      #             data = f.read()
      #         self.storage_manager.store(
      #         f"{self.build_config.project_name}/{name}", data)

      return Result(True,
                    "Build completed successfully",
                    metadata=build_metadata)

    except Exception as e:
      self.logger.error("Build failed: %s", e)
      return Result(False, f"Build failed: {e}")

  def clean(self) -> bool:
    """Clean up build artifacts and temporary files."""
    try:
      # Clean up local artifacts
      for path in self._artifacts.values():
        if path.exists():
          path.unlink()

      self._artifacts.clear()
      self.logger.info("Cleanup completed successfully")
      return True

    except Exception as e:
      self.logger.error("Cleanup failed: %s", e)
      return False

  def get_build_artifacts(self) -> Dict[str, Path]:
    """Get build artifacts."""
    return self._artifacts.copy()

  def prepare_build_environment(self) -> bool:
    """Prepare the build environment."""
    try:
      # Set up environment variables
      env_vars = {
          'CC': 'clang',
          'CXX': 'clang++',
          'SANITIZER': self.build_config.sanitizer.value,
          'FUZZING_ENGINE': self.build_config.fuzzing_engine.value,
          'ARCHITECTURE': self.build_config.architecture
      }
      env_vars.update(self.build_config.environment_vars)

      self.logger.debug("Prepared environment variables: %s", env_vars)
      return True

    except Exception as e:
      self.logger.error("Failed to prepare build environment: %s", e)
      return False

  def execute_build_command(self, command: List[str]) -> CommandResult:
    """Execute a build command."""
    image_name = (f"{self.build_config.project_name}:"
                  f"{self.build_config.sanitizer.value}")

    # Set up volume mounts
    mounts = {str(Path.cwd()): "/workspace"}

    return self.docker_manager.run_command(image_name, command, mounts)

  def process_build_artifacts(self) -> Dict[str, Path]:
    """Process build artifacts."""
    artifacts = {}

    # Look for common artifact patterns
    artifact_patterns = ["**/*_fuzzer", "**/*.so", "**/*.a"]

    workspace_path = Path.cwd()
    for pattern in artifact_patterns:
      for artifact_path in workspace_path.glob(pattern):
        if artifact_path.is_file():
          artifacts[artifact_path.name] = artifact_path

    self.logger.debug("Found %s artifacts", len(artifacts))
    return artifacts

  def _create_default_dockerfile(self, target: FuzzTarget,
                                 sanitizer: Sanitizer) -> Path:
    """Create a default Dockerfile for the target."""
    dockerfile_content = f"""
FROM gcr.io/oss-fuzz/{self.build_config.project_name}

# Set up environment
ENV SANITIZER={sanitizer.value}
ENV FUZZING_ENGINE={self.build_config.fuzzing_engine.value}
ENV ARCHITECTURE={self.build_config.architecture}

# Copy source code
COPY . /src

# Set working directory
WORKDIR /src

# Default build command
RUN compile
"""

    if target.build_artifacts_path is None:
      raise ValueError("Target build_artifacts_path is not set")
    dockerfile_path = Path(target.build_artifacts_path) / "Dockerfile.generated"
    with open(dockerfile_path, 'w') as f:
      f.write(dockerfile_content.strip())

    return dockerfile_path

  def build_local(self,
                  source_code: str,
                  benchmark_target_name: str,
                  sanitizer: str = 'address') -> Tuple[bool, Dict[str, Any]]:
    """
    Build a fuzz target locally, focusing only on the build process.

    Args:
        source_code: Fuzz target source code
        benchmark_target_name: Name of the benchmark target
        sanitizer: Sanitizer to use (default: 'address')

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and build metadata
    """
    self.logger.info('Building %s locally.', benchmark_target_name)

    # Generate unique project name
    generated_project = f'{self.build_config.project_name}-{uuid.uuid4().hex}'
    generated_project = FileUtils.rectify_docker_tag(generated_project)

    # Create OSS-Fuzz project
    generated_project_path = FileUtils.create_ossfuzz_project(
        self.build_config.project_name, generated_project)

    # Copy target to project
    target_destination = os.path.join(generated_project_path,
                                      f'{benchmark_target_name}.cc')
    with open(target_destination, 'w') as dst:
      dst.write(source_code)

    # Build the target
    if not self.build_target_local(generated_project, sanitizer):
      return False, {'error': 'Build failed'}

    # Prepare build metadata for the runner
    build_metadata = {
        'build_succeeded':
            True,
        'generated_project':
            generated_project,
        'generated_project_path':
            generated_project_path,
        'target_name':
            benchmark_target_name,
        'sanitizer':
            sanitizer,
        'build_artifacts_dir':
            self.docker_manager.get_build_artifact_dir(generated_project,
                                                       sanitizer),
        # 'fuzzer_binary_path': os.path.join(
        #     self.docker_manager.get_build_artifact_dir(
        #     generated_project, sanitizer),
        #     benchmark_target_name
        # ),
    }

    # The LocalRunner will use the build_metadata to execute the fuzzer and
    # collect results

    self.logger.info('Built %s locally successfully.', benchmark_target_name)
    return True, build_metadata

  def build_target_local(self,
                         generated_project: str,
                         sanitizer: str = 'address') -> bool:
    """Builds a target with OSS-Fuzz."""
    self.logger.info('Building %s with %s', generated_project, sanitizer)

    # Check for cached images and prepare build
    if (self.docker_manager.cache_enabled and
        self.docker_manager.is_image_cached(self.build_config.project_name,
                                            sanitizer)):
      self.logger.info('Using cached instance.')
      # In a real implementation, this would handle cached builds
    else:
      self.logger.info('The project does not have any cache')

    # Build fuzzers using OSS-Fuzz
    success = self.docker_manager.build_fuzzers(generated_project, sanitizer)
    if success:
      self.logger.info('Built target %s successfully', generated_project)
    else:
      self.logger.error('Failed to build target %s', generated_project)

    return success


class CloudBuilder(Builder):
  """
  Cloud builder implementation that uses CloudBuildManager for building fuzz
  targets.

  This class handles building fuzz targets in cloud environments,
  following the UML specification.
  """

  def __init__(self, storage_manager: StorageManager, build_config: BuildConfig,
               cloud_build_manager: CloudBuildManager):
    """
    Initialize the cloud builder.

    Args:
        storage_manager: Storage manager for artifacts
        build_config: Build configuration
        cloud_build_manager: Cloud build manager for cloud operations
    """
    super().__init__(storage_manager, build_config)
    self.project_id = cloud_build_manager.project_id
    self.region = cloud_build_manager.region
    self.bucket_name = f"{self.project_id}-build-artifacts"
    self.cloud_build_manager = cloud_build_manager
    self._artifacts: Dict[str, Path] = {}

    self.logger.debug("Initialized CloudBuilder for project %s in region %s",
                      self.project_id, self.region)

  def setup_environment(self) -> bool:
    """Set up the cloud build environment."""
    try:
      self.logger.info("Setting up cloud build environment for project %s",
                       self.build_config.project_name)
      # Cloud environment setup would involve checking credentials,
      # permissions, etc.
      return True
    except Exception as e:
      self.logger.error("Failed to setup cloud environment: %s", e)
      return False

  def build(self, target: FuzzTarget, sanitizer: Sanitizer) -> Result:
    """Build a fuzz target using cloud build."""
    try:
      self.logger.info("Starting cloud build for target %s with sanitizer %s",
                       target.name, sanitizer.value)

      # Prepare build environment
      if not self.prepare_build_environment():
        return Result(False, "Failed to prepare build environment")

      # Use the build_cloud method (focused only on building)
      success, build_metadata = self.build_cloud(
          source_code=target.source_code,
          target_path=target.target_path,
          benchmark_target_name=target.name,
          sanitizer=sanitizer.value)

      if not success:
        error_msg = build_metadata.get('error', 'Cloud build failed')
        return Result(False, error_msg)

      # Process build artifacts
      artifacts = self._process_cloud_build_artifacts(build_metadata)
      self._artifacts.update(artifacts)

      # Store artifacts in storage manager
      # for name, path in artifacts.items():
      #     if path.exists():
      #         with open(path, 'rb') as f:
      #             data = f.read()
      #         self.storage_manager.store(
      #         f"{self.build_config.project_name}/{name}", data)

      # TODO: Running should be handled separately by CloudRunner
      # The build_metadata contains all necessary information for the runner

      return Result(True, "Cloud build completed successfully", artifacts,
                    build_metadata)

    except Exception as e:
      self.logger.error("Cloud build failed: %s", e)
      return Result(False, f"Cloud build failed: {e}")

  def build_cloud(self,
                  source_code: str,
                  target_path: str,
                  benchmark_target_name: str,
                  sanitizer: str = 'address') -> Tuple[bool, Dict[str, Any]]:
    """
    Build a fuzz target in the cloud, focusing only on the build process.

    Args:
        source_code: Source code of the fuzz target
        target_path: Path to the target file
        benchmark_target_name: Name of the benchmark target
        sanitizer: Sanitizer to use (default: 'address')

    Returns:
        Tuple[bool, Dict[str, Any]]: Success status and build metadata
    """
    self.logger.info('Building %s in the cloud.', benchmark_target_name)

    # Generate unique identifiers for this build
    uid = f"{self.cloud_build_manager.experiment_name}-{uuid.uuid4()}"

    # Define cloud storage paths for build artifacts
    build_log_name = f'{uid}.build.log'
    build_log_path = (f'gs://{self.cloud_build_manager.experiment_bucket}'
                      f'/{build_log_name}')

    # Generate unique project name
    generated_project = f'{self.build_config.project_name}-{uuid.uuid4().hex}'
    generated_project = FileUtils.rectify_docker_tag(generated_project)

    # Create OSS-Fuzz project
    generated_project_path = FileUtils.create_ossfuzz_project(
        self.build_config.project_name, generated_project)

    # Copy target to project
    target_destination = os.path.join(generated_project_path,
                                      f'{benchmark_target_name}.cc')
    with open(target_destination, 'w') as dst:
      dst.write(source_code)

    # Build the command for cloud build (build-only, no running)
    command = self.cloud_build_manager.build_cloud_build_command(
        generated_project,
        benchmark_target_name,
        self.build_config.project_name,
    )

    self.logger.info('Cloud build command: %s', command)

    # Execute cloud build with retry control
    if not self.cloud_build_manager.run_with_retry_control(
        target_path, command):
      return False, {'error': 'Cloud build execution failed'}

    # Prepare build metadata for the runner
    build_metadata = {
        'build_succeeded': True,
        'generated_project': generated_project,
        'target_name': benchmark_target_name,
        'sanitizer': sanitizer,
        'build_log_path': build_log_path,
        'build_log_name': build_log_name,
        'experiment_bucket': self.cloud_build_manager.experiment_bucket,
        'experiment_name': self.cloud_build_manager.experiment_name,
        'uid': uid,
    }

    # The CloudRunner will use the build_metadata to execute the fuzzer in
    # the cloud and collect results

    self.logger.info('Built %s in the cloud successfully.',
                     os.path.realpath(target_path))
    return True, build_metadata

  def clean(self) -> bool:
    """Clean up cloud build artifacts."""
    try:
      # Clean up local artifacts
      for path in self._artifacts.values():
        if path.exists():
          path.unlink()

      self._artifacts.clear()
      self.logger.info("Cloud build cleanup completed successfully")
      return True

    except Exception as e:
      self.logger.error("Cloud build cleanup failed: %s", e)
      return False

  def get_build_artifacts(self) -> Dict[str, Path]:
    """Get cloud build artifacts."""
    return self._artifacts.copy()

  def prepare_build_environment(self) -> bool:
    """Prepare the cloud build environment."""
    try:
      # Set up cloud-specific environment
      self.logger.debug("Preparing cloud build environment for %s",
                        self.build_config.project_name)
      return True

    except Exception as e:
      self.logger.error("Failed to prepare cloud build environment: %s", e)
      return False

  def execute_build_command(self, command: List[str]) -> CommandResult:
    """Execute a build command in the cloud."""
    # In cloud builds, commands are typically executed as part of the cloud
    # build process. This is a placeholder that would integrate with the cloud
    # build manager
    self.logger.info("Executing cloud build command: %s", ' '.join(command))

    # For now, return a success result
    return CommandResult(stdout="Cloud build command executed",
                         stderr="",
                         return_code=0,
                         success=True)

  def process_build_artifacts(self) -> Dict[str, Path]:
    """Process cloud build artifacts."""
    artifacts = {}

    # In a real implementation, this would download artifacts from cloud storage
    # For now, create placeholder artifacts
    artifact_name = f"{self.build_config.project_name}_fuzzer"
    artifact_path = Path(f"/tmp/{artifact_name}")

    # Create a dummy artifact file
    with open(artifact_path, 'w') as f:
      f.write("cloud build artifact")

    artifacts[artifact_name] = artifact_path

    self.logger.debug("Processed %s cloud build artifacts", len(artifacts))
    return artifacts

  def _process_cloud_build_artifacts(self, build_metadata: Dict[str, Any]) -> \
      Dict[str, Path]:
    """Process artifacts from cloud build metadata (build-only, no running
    artifacts)."""
    artifacts = {}

    # Process build log
    if build_metadata.get('build_log_path'):
      # Download build log from cloud storage
      build_log_name = build_metadata.get('build_log_name')
      if build_log_name:
        build_log_local = Path(
            f"/tmp/{build_metadata.get('target_name', 'unknown')}_build.log")
        # TODO: Implement actual download from cloud storage
        # For now, create a placeholder
        build_log_local.touch()
        artifacts['build_log'] = build_log_local

    # Process generated project metadata
    if build_metadata.get('generated_project'):
      # The generated project exists in the cloud build environment
      # Store metadata for potential future use
      artifacts['build_metadata'] = Path(
          f"/tmp/{build_metadata['generated_project']}_metadata.json")
      # TODO: Save build metadata to file for runner consumption

    self.logger.debug("Processed %s cloud build artifacts", len(artifacts))
    return artifacts

  def _create_build_config(self, target: FuzzTarget, sanitizer: Sanitizer) -> \
      Dict[str, Any]:
    """Create cloud build configuration."""
    return {
        'project_name': self.build_config.project_name,
        'target_name': target.name,
        'sanitizer': sanitizer.value,
        'language': self.build_config.language,
        'fuzzing_engine': self.build_config.fuzzing_engine.value,
        'architecture': self.build_config.architecture,
        'environment_vars': self.build_config.environment_vars,
        'build_args': self.build_config.build_args
    }
