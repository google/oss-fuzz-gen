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
Docker management subsystem for the Custom Fuzzing Module build system.

This module provides a clean abstraction for managing Docker containers used
in the OSS-Fuzz build process. It handles image building, container creation,
execution, and cleanup, while maintaining loose coupling with the underlying
Docker infrastructure.

The DockerManager is designed to be:
1. Simple - providing a straightforward API for Docker operations
2. Robust - with proper error handling and logging
3. Flexible - supporting various Docker configurations and options

This implementation maintains loose coupling with OSS-Fuzz internals while
providing the functionality needed for build and test environments.
"""

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# Configure module logger
logger = logging.getLogger("ossfuzz_sdk.docker_manager")

# Import consolidated errors
from ossfuzz_py.errors import (
    DockerContainerError,
    DockerExecutionError,
    DockerImageError,
    DockerManagerError,
)

# Import centralized environment utilities
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.env_vars import EnvVars

# Constants from the original implementation
BUILD_DIR = "build"
ENABLE_CACHING = EnvUtils.get_env_bool(EnvVars.OFG_USE_CACHING, default=True)
CLEAN_UP_OSS_FUZZ = EnvUtils.get_env_bool(EnvVars.OFG_CLEAN_UP_OSS_FUZZ, default=True)


@dataclass
class CommandResult:
    """Result of a command execution."""

    stdout: str
    stderr: str
    return_code: int
    success: bool

    @property
    def output(self) -> str:
        """Combined stdout and stderr output."""
        return f"{self.stdout}\n{self.stderr}".strip()


class DockerManager:
    """
    Manages Docker images and containers for the build process according to UML
    specification.

    This class provides a high-level interface for Docker operations
    used in the OSS-Fuzz build process, abstracting the complexities
    of the Docker CLI. Enhanced with OSS-Fuzz specific functionality.
    """

    def __init__(self, cache_enabled: bool = True, oss_fuzz_dir: Optional[str] = None):
        """
        Initialize the Docker manager.

        Args:
            cache_enabled: Whether to enable image caching
            oss_fuzz_dir: Path to OSS-Fuzz directory

        Raises:
            DockerManagerError: If Docker is not available.
        """
        self.cache_enabled = cache_enabled
        self.oss_fuzz_dir = oss_fuzz_dir or EnvUtils.get_oss_fuzz_dir()
        self.logger = logger
        self.container_ids = []

        # Verify Docker is installed and running
        try:
            self._run_docker_command(["--version"])
            self.logger.debug(
                "Docker manager initialized with cache_enabled=%s", cache_enabled
            )
        except DockerExecutionError:
            self.logger.error(
                "Docker is not available. "
                "Please ensure Docker is installed and running."
            )
            raise DockerManagerError(
                "Docker is not available. "
                "Please ensure Docker is installed and running."
            )

    def build_image(self, project: str, tag: str, dockerfile: Path) -> bool:
        """
        Build a Docker image for a project.

        Args:
            project: Project name
            tag: Image tag
            dockerfile: Path to Dockerfile

        Returns:
            bool: True if build was successful
        """
        image_name = f"{project}:{tag}"
        self.logger.info("Building Docker image: %s", image_name)

        # Check if image is cached and caching is enabled
        if self.cache_enabled and self.image_exists(image_name):
            self.logger.info("Using cached image: %s", image_name)
            return True

        # Prepare build command
        cmd = ["build", "-t", image_name, "-f", str(dockerfile), str(dockerfile.parent)]

        try:
            self.logger.debug("Executing build command: docker %s", " ".join(cmd))
            result = self._run_docker_command(cmd)
            self.logger.info(
                "Successfully built image: %s, result: %s", image_name, result
            )
            return True
        except DockerExecutionError as e:
            self.logger.error("Docker build failed: %s", str(e))
            return False

    def remove_container(self, container_id: str, force: bool = False) -> None:
        """
        Remove a Docker container.

        Args:
            container_id: ID of the container to remove.
            force: Whether to force removal.

        Raises:
            DockerContainerError: If removal fails.
        """
        self.logger.info("Removing container: %s", container_id)

        cmd = ["docker", "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_id)

        try:
            self._run_docker_command(cmd[1:])  # Remove 'docker' from the list
            if container_id in self.container_ids:
                self.container_ids.remove(container_id)
            self.logger.debug("Container removed: %s", container_id)
        except DockerExecutionError as e:
            self.logger.error("Failed to remove container: %s", str(e))
            raise DockerContainerError(f"Failed to remove container: {str(e)}")

    def remove_image(self, project: str, tag: str, force: bool = False) -> None:
        """
        Remove the Docker image.

        Args:
            force: Whether to force removal.

        Raises:
            DockerImageError: If removal fails.
        """
        image_name = f"{project}:{tag}"
        self.logger.info("Removing image: %s", image_name)

        cmd = ["docker", "rmi"]
        if force:
            cmd.append("-f")
        cmd.append(image_name)

        try:
            self._run_docker_command(cmd[1:])  # Remove 'docker' from the list
            self.logger.debug("Image removed: %s", image_name)
        except DockerExecutionError as e:
            self.logger.error("Failed to remove image: %s", str(e))
            raise DockerImageError(f"Failed to remove image: {str(e)}")

    def get_logs(
        self, container_id: str, follow: bool = False, tail: Optional[str] = None
    ) -> str:
        """
        Retrieve logs from a running or stopped container.

        Args:
            container_id: ID of the container to get logs from.
            follow: Whether to follow log output.
            tail: Number of lines to show from the end (e.g., '100', 'all').

        Returns:
            Log output as a string.

        Raises:
            DockerContainerError: If log retrieval fails.
        """
        self.logger.debug("Getting logs for container: %s", container_id)

        cmd = ["docker", "logs"]

        if follow:
            cmd.append("-f")

        if tail:
            cmd.extend(["--tail", tail])

        cmd.append(container_id)

        try:
            logs = self._run_docker_command(cmd[1:])  # Remove 'docker' from the list
            return logs
        except DockerExecutionError as e:
            self.logger.error("Failed to get logs: %s", str(e))
            raise DockerContainerError(f"Failed to get logs from container: {str(e)}")

    def copy_from_container(
        self, container_id: str, container_path: str, host_path: str
    ) -> None:
        """
        Copy files from a container to the host.

        Args:
            container_id: ID of the container to copy from.
            container_path: Path in the container to copy from.
            host_path: Path on the host to copy to.

        Raises:
            DockerContainerError: If the copy operation fails.
        """
        self.logger.info(
            "Copying from container %s: %s -> %s",
            container_id,
            container_path,
            host_path,
        )

        cmd = ["docker", "cp", f"{container_id}:{container_path}", host_path]

        try:
            self._run_docker_command(cmd[1:])  # Remove 'docker' from the list
            self.logger.debug("Files copied from container %s", container_id)
        except DockerExecutionError as e:
            self.logger.error("Failed to copy from container: %s", str(e))
            raise DockerContainerError(f"Failed to copy files from container: {str(e)}")

    def cleanup(self) -> None:
        """
        Clean up all resources created by this manager.

        This method removes all containers created by this manager
        and then removes the image.
        """
        self.logger.info("Cleaning up Docker resources")

        # Remove all containers
        for container_id in self.container_ids[:]:
            try:
                self.remove_container(container_id, force=True)
            except DockerContainerError as e:
                self.logger.warning(
                    "Failed to remove container during cleanup: %s", str(e)
                )

    def _run_docker_command(self, args: List[str]) -> str:
        """
        Run a Docker command and return its output.

        Args:
            args: Docker command arguments (without 'docker' prefix).

        Returns:
            Command output as a string.

        Raises:
            DockerExecutionError: If the command fails.
        """
        cmd = ["docker"] + args

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            raise DockerExecutionError(f"Docker command failed: {error_msg}")
        except FileNotFoundError:
            raise DockerExecutionError(
                "Docker executable not found. Is Docker installed?"
            )

    def image_exists(self, image_name: str) -> bool:
        """Check if a Docker image exists locally."""
        try:
            result = self._run_docker_command(["images", "-q", image_name])
            return bool(result.strip())
        except DockerExecutionError:
            return False

    def tag_image(self, source: str, target: str) -> bool:
        """
        Tag an existing image with a new name.

        Args:
            source: Source image name
            target: Target image name

        Returns:
            bool: True if tagging was successful
        """
        try:
            self.logger.info("Tagging image %s as %s", source, target)
            self._run_docker_command(["tag", source, target])
            self.logger.debug("Successfully tagged image: %s -> %s", source, target)
            return True
        except DockerExecutionError as e:
            self.logger.error("Failed to tag image: %s", e)
            return False

    def run_command(
        self, image: str, command: List[str], mounts: Optional[Dict[str, str]] = None
    ) -> CommandResult:
        """
        Run a command in a Docker container.

        Args:
            image: Docker image to use
            command: Command to execute
            mounts: Dictionary of host_path:container_path mounts

        Returns:
            CommandResult: Result of the command execution
        """
        try:
            cmd = ["run", "--rm"]

            # Add volume mounts
            if mounts:
                for host_path, container_path in mounts.items():
                    cmd.extend(["-v", f"{host_path}:{container_path}"])

            cmd.append(image)
            cmd.extend(command)

            self.logger.debug("Running command: docker %s", " ".join(cmd))

            # Use subprocess directly to get both stdout and stderr
            full_cmd = ["docker"] + cmd
            result = subprocess.run(
                full_cmd, capture_output=True, check=True, text=True
            )

            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                success=result.returncode == 0,
            )

        except Exception as e:
            self.logger.error("Failed to run command: %s", e)
            return CommandResult(
                stdout="", stderr=str(e), return_code=-1, success=False
            )

    def prepare_project_image(self, project: str) -> str:
        """
        Prepare a project image for building.

        Args:
            project: Project name

        Returns:
            str: Image name that was prepared
        """
        base_image = f"gcr.io/oss-fuzz/{project}"

        # Check if base image exists
        if not self.image_exists(base_image):
            self.logger.warning("Base image %s not found locally", base_image)
            # In a real implementation, this might pull the image
            # For now, we'll use a generic base image
            base_image = "ubuntu:20.04"

        self.logger.info("Prepared project image: %s", base_image)
        return base_image

    def is_image_cached(self, project_name: str, sanitizer: str) -> bool:
        """
        Check if an image is cached for a project and sanitizer.

        Args:
            project_name: Project name
            sanitizer: Sanitizer name

        Returns:
            bool: True if image is cached
        """
        if not self.cache_enabled:
            return False

        cached_image_name = self._get_project_cache_image_name(project_name, sanitizer)
        return self.image_exists(cached_image_name)

    # OSS-Fuzz specific methods
    def _get_project_cache_name(self, project: str) -> str:
        """Gets name of cached container for a project."""
        return f"gcr.io.oss-fuzz.{project}_cache"

    def _get_project_cache_image_name(self, project: str, sanitizer: str) -> str:
        """Gets name of cached Docker image for a project and
        the respective sanitizer."""
        return (
            "us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/"
            f"{project}-ofg-cached-{sanitizer}"
        )

    def get_project_language(self, project: str) -> str:
        """Returns the project language read from its project.yaml."""
        project_yaml_path = os.path.join(
            self.oss_fuzz_dir, "projects", project, "project.yaml"
        )
        if not os.path.isfile(project_yaml_path):
            self.logger.warning(
                "Failed to find the project yaml of %s, assuming it is C++", project
            )
            return "C++"

        with open(project_yaml_path, "r") as benchmark_file:
            data = yaml.safe_load(benchmark_file)
            return data.get("language", "C++")

    def get_project_repository(self, project: str) -> str:
        """Returns the project repository read from its project.yaml."""
        project_yaml_path = os.path.join(
            self.oss_fuzz_dir, "projects", project, "project.yaml"
        )
        if not os.path.isfile(project_yaml_path):
            self.logger.warning(
                "Failed to find the project yaml of %s, return empty repository",
                project,
            )
            return ""

        with open(project_yaml_path, "r") as benchmark_file:
            data = yaml.safe_load(benchmark_file)
            return data.get("main_repo", "")

    def build_oss_fuzz_image(self, project_name: str) -> str:
        """Builds project image in OSS-Fuzz."""
        adjusted_env = os.environ.copy()
        adjusted_env["FUZZING_LANGUAGE"] = self.get_project_language(project_name)
        venv_dir = EnvUtils.get_venv_dir()

        command = [
            f"{venv_dir}/bin/python3",
            "infra/helper.py",
            "build_image",
            "--pull",
            project_name,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=self.oss_fuzz_dir,
                env=adjusted_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
            self.logger.info(
                "Successfully built project image: %s, result: %s", project_name, result
            )
            return f"gcr.io/oss-fuzz/{project_name}"
        except subprocess.CalledProcessError as e:
            self.logger.error(
                "Failed to build project image for %s: %s", project_name, e.stderr
            )
            return ""

    def build_fuzzers(self, project_name: str, sanitizer: str = "address") -> bool:
        """Build fuzzers for a project using OSS-Fuzz."""
        adjusted_env = os.environ.copy()
        adjusted_env["FUZZING_LANGUAGE"] = self.get_project_language(project_name)
        venv_dir = EnvUtils.get_venv_dir()

        command = [
            f"{venv_dir}/bin/python3",
            "infra/helper.py",
            "build_fuzzers",
            project_name,
            "--sanitizer",
            sanitizer,
        ]

        try:
            result = subprocess.run(
                command,
                cwd=self.oss_fuzz_dir,
                env=adjusted_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
            self.logger.info(
                "Successfully built fuzzers: %s, sanitizer: %s, result: %s",
                project_name,
                sanitizer,
                result,
            )
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(
                "Failed to build fuzzers for %s: %s", project_name, e.stderr
            )
            return False

    def get_build_artifact_dir(
        self, generated_project: str, build_artifact: str
    ) -> str:
        """Returns the build artifact absolute directory path for
        generated_project."""
        return os.path.join(
            self.oss_fuzz_dir, "build", build_artifact, generated_project
        )
