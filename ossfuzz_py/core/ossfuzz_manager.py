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
OSS-Fuzz Manager for the OSS-Fuzz SDK.

This module manages local OSS-Fuzz repository states, parses project
configurations and abstracts build environments. It provides the main interface
for interacting with OSS-Fuzz projects and tracking their configurations over
time.
"""

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ossfuzz_py.errors import OSSFuzzManagerError

# Configure module logger
logger = logging.getLogger("ossfuzz_sdk.ossfuzz_manager")


class OSSFuzzManager:
    """
    Manages local OSS-Fuzz repository states and project configurations.

    This class provides the main interface for managing OSS-Fuzz projects,
    including repository management, project discovery, configuration parsing,
    and change tracking capabilities.

    Attributes:
        checkout_path: Path to the OSS-Fuzz repository checkout
        cache_dir: Directory for caching data
        temp_dir: Temporary directory for operations
        oss_fuzz_dir: Name of the OSS-Fuzz directory
        clean_up_on_exit: Whether to clean up temporary files on exit
    """

    def __init__(self, checkout_path: Optional[Path] = None, use_temp: bool = False):
        """
        Initialize OSS-Fuzz manager.

        Args:
            checkout_path: Path to the OSS-Fuzz repository checkout
            use_temp: Whether to use a temporary directory

        Raises:
            OSSFuzzManagerError: If initialization fails
        """
        self.logger = logger
        self.oss_fuzz_dir = "oss-fuzz"
        self.clean_up_on_exit = use_temp

        if use_temp:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="ossfuzz_"))
            self.checkout_path = self.temp_dir / self.oss_fuzz_dir
        else:
            if checkout_path is None:
                checkout_path = Path.cwd() / self.oss_fuzz_dir
            self.checkout_path = Path(checkout_path)

        self.logger.info(
            "Initialized OSSFuzzManager with checkout at %s", self.checkout_path
        )

    def clone(self, version: str = "master") -> bool:
        """
        Clone the OSS-Fuzz repository.

        Args:
            version: Git branch or tag to clone

        Returns:
            bool: True if successful

        Raises:
            OSSFuzzManagerError: If cloning fails
        """
        try:
            if self.checkout_path.exists():
                self.logger.info("Repository already exists at %s", self.checkout_path)
                return True

            repo_url = "https://github.com/google/oss-fuzz.git"
            cmd = [
                "git",
                "clone",
                "--branch",
                version,
                repo_url,
                str(self.checkout_path),
            ]

            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(
                "Successfully cloned OSS-Fuzz repository to %s", self.checkout_path
            )
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to clone repository: {e.stderr}"
            self.logger.error(error_msg)
            raise OSSFuzzManagerError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during clone: {str(e)}"
            self.logger.error(error_msg)
            raise OSSFuzzManagerError(error_msg)

    def get_project_path(self, project_name: str) -> Path:
        """
        Get the path to a specific project.

        Args:
            project_name: Name of the project

        Returns:
            Path: Path to the project directory

        Raises:
            OSSFuzzManagerError: If project is not found
        """
        if not self.checkout_path.exists():
            raise OSSFuzzManagerError("OSS-Fuzz repository not found")

        project_path = self.checkout_path / "projects" / project_name
        if not project_path.exists():
            raise OSSFuzzManagerError(f"Project '{project_name}' not found")

        return project_path

    def _is_valid_project_directory(self, project_dir: Path) -> bool:
        """Check if a directory is a valid OSS-Fuzz project."""
        if not project_dir.is_dir() or project_dir.name.startswith("."):
            return False

        has_yaml = (project_dir / "project.yaml").exists()
        has_dockerfile = (project_dir / "Dockerfile").exists()
        return has_yaml or has_dockerfile

    def _matches_language_filter(
        self, project_name: str, language: Optional[str]
    ) -> bool:
        """Check if a project matches the language filter."""
        if language is None:
            return True

        project_lang = self.get_project_language(project_name)
        return project_lang.lower() == language.lower()

    def list_projects(self, language: Optional[str] = None) -> List[str]:
        """
        List all OSS-Fuzz projects, optionally filtered by language.

        Args:
            language: Optional language filter

        Returns:
            List of project names

        Raises:
            OSSFuzzManagerError: If project listing fails
        """
        if not self.checkout_path.exists():
            raise OSSFuzzManagerError("OSS-Fuzz repository not found")

        try:
            projects_dir = self.checkout_path / "projects"
            if not projects_dir.exists():
                raise OSSFuzzManagerError("Projects directory not found in repository")

            projects = []
            for item in projects_dir.iterdir():
                if not self._is_valid_project_directory(item):
                    continue

                if self._matches_language_filter(item.name, language):
                    projects.append(item.name)

            self.logger.debug("Found %d projects in OSS-Fuzz repository", len(projects))
            return sorted(projects)

        except Exception as e:
            self.logger.error("Failed to list projects: %s", str(e))
            raise OSSFuzzManagerError(f"Project listing failed: {str(e)}")

    def get_project_config(self, project_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific project.

        Args:
            project_name: Name of the project

        Returns:
            Dict: Project configuration

        Raises:
            OSSFuzzManagerError: If configuration retrieval fails
        """
        try:
            project_path = self.get_project_path(project_name)
            config_file = project_path / "project.yaml"

            if config_file.exists():
                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)
                return config or {}
            # Return basic config if no project.yaml exists
            return {
                "project_name": project_name,
                "language": self.get_project_language(project_name),
                "main_repo": self.get_project_repository(project_name),
            }

        except Exception as e:
            self.logger.error(
                "Failed to get project config for '%s': %s", project_name, str(e)
            )
            raise OSSFuzzManagerError(f"Failed to get project config: {str(e)}")

    def get_project_repository(self, project_name: str) -> str:
        """
        Get the repository URL for a project.

        Args:
            project_name: Name of the project

        Returns:
            str: Repository URL
        """
        try:
            config = self.get_project_config(project_name)
            return config.get("main_repo", "")
        except Exception:
            return ""

    def get_project_language(self, project_name: str) -> str:
        """
        Get the primary language for a project.

        Args:
            project_name: Name of the project

        Returns:
            str: Primary language
        """
        try:
            config = self.get_project_config(project_name)
            return config.get("language", "c++")
        except Exception:
            return "c++"

    def update_repository(self) -> bool:
        """
        Update the local OSS-Fuzz repository.

        Returns:
            bool: True if update was successful

        Raises:
            OSSFuzzManagerError: If update fails
        """
        if not self.checkout_path.exists():
            raise OSSFuzzManagerError("OSS-Fuzz repository not found")

        try:
            cmd = ["git", "pull"]
            subprocess.run(
                cmd, cwd=self.checkout_path, capture_output=True, text=True, check=True
            )
            self.logger.info("Successfully updated OSS-Fuzz repository")
            return True

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to update repository: {e.stderr}"
            self.logger.error(error_msg)
            raise OSSFuzzManagerError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during update: {str(e)}"
            self.logger.error(error_msg)
            raise OSSFuzzManagerError(error_msg)

    def postprocess(self) -> bool:
        """
        Perform post-processing operations.

        Returns:
            bool: True if successful
        """
        try:
            # Cleanup temporary files if needed
            if self.clean_up_on_exit and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.logger.info("Cleaned up temporary files")
            return True
        except Exception as e:
            self.logger.warning("Post-processing failed: %s", str(e))
            return False

    def __del__(self):
        """Cleanup on destruction."""
        if hasattr(self, "clean_up_on_exit") and self.clean_up_on_exit:
            self.postprocess()
