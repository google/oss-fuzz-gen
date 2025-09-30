"""
Work Directory Management utilities for the OSS-Fuzz SDK.

This module provides utilities for managing working directories, including
creation, validation, cleanup operations, and temporary directory management.
It ensures proper error handling for permission issues and edge cases.

The WorkDirManager handles:
1. Working directory creation and validation
2. Path normalization and safety checks
3. Temporary directory management
4. Cleanup operations with proper error handling
5. Directory structure management for different SDK operations
"""

import logging
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Import consolidated errors
from ossfuzz_py.errors import (WorkDirError, WorkDirPermissionError,
                               WorkDirValidationError)

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.work_dir_manager')

class WorkDirManager:
  """
  Manages working directories for OSS-Fuzz SDK operations.

  This class provides utilities for creating, validating, and managing
  working directories used by various SDK components. It ensures proper
  directory structure, permissions, and cleanup.

  Example:
      ```python
      # Create a work directory manager
      work_mgr = WorkDirManager('/tmp/ossfuzz_work')

      # Create a project work directory
      project_dir = work_mgr.create_project_dir('libpng')

      # Create a build work directory
      build_dir = work_mgr.create_build_dir('libpng', 'build_001')

      # Create a temporary directory
      with work_mgr.temp_dir() as temp_dir:
          # Use temporary directory
          pass

      # Cleanup all directories
      work_mgr.cleanup_all()
      ```
  """

  def __init__(self, base_dir: Union[str, Path], auto_create: bool = True):
    """
    Initialize the WorkDirManager.

    Args:
        base_dir: Base directory for all work directories
        auto_create: Whether to automatically create the base directory

    Raises:
        WorkDirError: If initialization fails
    """
    self.base_dir = Path(base_dir).resolve()
    self.logger = logger
    self._created_dirs: List[Path] = []
    self._temp_dirs: List[Path] = []

    if auto_create:
      self.create_base_dir()
    else:
      self.validate_base_dir()

    self.logger.info("WorkDirManager initialized with base directory: %s",
                     self.base_dir)

  def create_base_dir(self) -> None:
    """
    Create the base directory if it doesn't exist.

    Raises:
        WorkDirPermissionError: If directory creation fails due to permissions
        WorkDirError: If directory creation fails for other reasons
    """
    try:
      self.base_dir.mkdir(parents=True, exist_ok=True)
      self.logger.debug("Base directory created/verified: %s", self.base_dir)
    except PermissionError as e:
      raise WorkDirPermissionError(
          f"Permission denied creating base directory {self.base_dir}: {str(e)}"
      )
    except Exception as e:
      raise WorkDirError(
          f"Failed to create base directory {self.base_dir}: {str(e)}")

  def validate_base_dir(self) -> None:
    """
    Validate that the base directory exists and is accessible.

    Raises:
        WorkDirValidationError: If validation fails
    """
    if not self.base_dir.exists():
      raise WorkDirValidationError(
          f"Base directory does not exist: {self.base_dir}")

    if not self.base_dir.is_dir():
      raise WorkDirValidationError(
          f"Base path is not a directory: {self.base_dir}")

    if not os.access(self.base_dir, os.R_OK | os.W_OK):
      raise WorkDirValidationError(
          f"Base directory is not readable/writable: {self.base_dir}")

    self.logger.debug("Base directory validated: %s", self.base_dir)

  def normalize_path(self, path: Union[str, Path]) -> Path:
    """
    Normalize and validate a path relative to the base directory.

    Args:
        path: Path to normalize (can be relative or absolute)

    Returns:
        Path: Normalized absolute path

    Raises:
        WorkDirValidationError: If path is invalid or outside base directory
    """
    path = Path(path)

    # If relative, make it relative to base directory
    if not path.is_absolute():
      path = self.base_dir / path

    # Resolve to absolute path
    path = path.resolve()

    # Ensure path is within base directory (security check)
    try:
      path.relative_to(self.base_dir)
    except ValueError:
      raise WorkDirValidationError(f"Path is outside base directory: {path}")

    return path

  def create_dir(self,
                 path: Union[str, Path],
                 parents: bool = True,
                 exist_ok: bool = True) -> Path:
    """
    Create a directory with proper error handling.

    Args:
        path: Directory path to create
        parents: Whether to create parent directories
        exist_ok: Whether to ignore if directory already exists

    Returns:
        Path: Created directory path

    Raises:
        WorkDirPermissionError: If creation fails due to permissions
        WorkDirError: If creation fails for other reasons
    """
    normalized_path = self.normalize_path(path)

    try:
      normalized_path.mkdir(parents=parents, exist_ok=exist_ok)
      self._created_dirs.append(normalized_path)
      self.logger.debug("Directory created: %s", normalized_path)
      return normalized_path
    except PermissionError as e:
      raise WorkDirPermissionError(
          f"Permission denied creating directory {normalized_path}: {str(e)}")
    except FileExistsError as e:
      if not exist_ok:
        raise WorkDirError(
            f"Directory already exists: {normalized_path}: {str(e)}")
      return normalized_path
    except Exception as e:
      raise WorkDirError(
          f"Failed to create directory {normalized_path}: {str(e)}")

  def create_project_dir(self, project_name: str) -> Path:
    """
    Create a project-specific work directory.

    Args:
        project_name: Name of the project

    Returns:
        Path: Created project directory
    """
    # Sanitize project name for filesystem
    safe_name = self._sanitize_name(project_name)
    project_path = self.create_dir(f"projects/{safe_name}")

    # Create standard subdirectories
    self.create_dir(project_path / "builds")
    self.create_dir(project_path / "runs")
    self.create_dir(project_path / "results")
    self.create_dir(project_path / "artifacts")

    self.logger.info("Project directory created: %s", project_path)
    return project_path

  def create_build_dir(self, project_name: str, build_id: str) -> Path:
    """
    Create a build-specific work directory.

    Args:
        project_name: Name of the project
        build_id: Build identifier

    Returns:
        Path: Created build directory
    """
    safe_project = self._sanitize_name(project_name)
    safe_build = self._sanitize_name(build_id)
    build_path = self.create_dir(f"projects/{safe_project}/builds/{safe_build}")

    # Create standard build subdirectories
    self.create_dir(build_path / "source")
    self.create_dir(build_path / "output")
    self.create_dir(build_path / "logs")

    self.logger.info("Build directory created: %s", build_path)
    return build_path

  def create_run_dir(self, project_name: str, target_name: str) -> Path:
    """
    Create a run-specific work directory.

    Args:
        project_name: Name of the project
        target_name: Run Target Name

    Returns:
        Path: Created run directory
    """
    safe_project = self._sanitize_name(project_name)
    safe_run = self._sanitize_name(target_name)
    run_path = self.create_dir(f"projects/{safe_project}/runs/{safe_run}")

    # Create standard run subdirectories
    self.create_dir(run_path / "corpus")
    self.create_dir(run_path / "crashes")
    self.create_dir(run_path / "coverage")
    self.create_dir(run_path / "logs")

    self.logger.info("Run directory created: %s", run_path)
    return run_path

  def get_run_corpus_dir(self, project_name: str, target_name: str) -> Path:
    project_dir = self.get_project_dir(project_name)
    if project_dir is None:
      raise ValueError(f"Project directory not found for: {project_name}")
    return project_dir / "runs" / target_name / "corpus"

  def get_run_logs_dir(self, project_name: str, target_name: str) -> Path:
    project_dir = self.get_project_dir(project_name)
    if project_dir is None:
      raise ValueError(f"Project directory not found for: {project_name}")
    return project_dir / "runs" / target_name / "logs"

  @contextmanager
  def temp_dir(self,
               prefix: str = "ossfuzz_",
               suffix: str = "",
               tmp_dir_path: Optional[Path] = None):
    """
    Create a temporary directory with automatic cleanup.

    Args:
        prefix: Prefix for the temporary directory name
        suffix: Suffix for the temporary directory name
        tmp_dir_path: Parent directory for the temporary directory

    Yields:
        Path: Temporary directory path
    """
    if tmp_dir_path is None:
      tmp_dir_path = self.base_dir / "temp"
      self.create_dir(tmp_dir_path)

    temp_dir = None
    try:
      temp_dir = Path(
          tempfile.mkdtemp(prefix=prefix, suffix=suffix, dir=str(tmp_dir_path)))
      self._temp_dirs.append(temp_dir)
      self.logger.debug("Temporary directory created: %s", temp_dir)
      yield temp_dir
    finally:
      if temp_dir and temp_dir.exists():
        try:
          shutil.rmtree(temp_dir)
          if temp_dir in self._temp_dirs:
            self._temp_dirs.remove(temp_dir)
          self.logger.debug("Temporary directory cleaned up: %s", temp_dir)
        except Exception as e:
          self.logger.warning("Failed to cleanup temporary directory %s: %s",
                              temp_dir, str(e))

  def cleanup_dir(self, path: Union[str, Path], force: bool = False) -> bool:
    """
    Clean up a specific directory.

    Args:
        path: Directory path to clean up
        force: Whether to force cleanup even if not created by this manager

    Returns:
        bool: True if cleanup was successful
    """
    normalized_path = self.normalize_path(path)

    if not force and normalized_path not in self._created_dirs:
      self.logger.warning(
          "Directory not created by this manager, skipping cleanup: %s",
          normalized_path)
      return False

    try:
      if normalized_path.exists():
        shutil.rmtree(normalized_path)
        if normalized_path in self._created_dirs:
          self._created_dirs.remove(normalized_path)
        self.logger.debug("Directory cleaned up: %s", normalized_path)
      return True
    except Exception as e:
      self.logger.error("Failed to cleanup directory %s: %s", normalized_path,
                        str(e))
      return False

  def cleanup_all(self, include_base: bool = False) -> None:
    """
    Clean up all directories created by this manager.

    Args:
        include_base: Whether to also remove the base directory
    """
    # Cleanup temporary directories first
    for temp_dir in self._temp_dirs[:]:
      self.cleanup_dir(temp_dir, force=True)

    # Cleanup created directories
    for created_dir in self._created_dirs[:]:
      self.cleanup_dir(created_dir, force=True)

    # Cleanup base directory if requested
    if include_base and self.base_dir.exists():
      try:
        shutil.rmtree(self.base_dir)
        self.logger.info("Base directory cleaned up: %s", self.base_dir)
      except Exception as e:
        self.logger.error("Failed to cleanup base directory %s: %s",
                          self.base_dir, str(e))

  def _sanitize_name(self, name: str) -> str:
    """
    Sanitize a name for use in filesystem paths.

    Args:
        name: Name to sanitize

    Returns:
        str: Sanitized name safe for filesystem use
    """
    # Replace unsafe characters with underscores
    sanitized = re.sub(r'[^\w\-_.]', '_', name)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    # Ensure it's not empty
    if not sanitized:
      sanitized = "unnamed"
    return sanitized

  def get_project_dir(self, project_name: str) -> Optional[Path]:
    """
    Get the path to a project directory if it exists.

    Args:
        project_name: Name of the project

    Returns:
        Optional[Path]: Project directory path if it exists, None otherwise
    """
    safe_name = self._sanitize_name(project_name)
    project_path = self.base_dir / "projects" / safe_name
    return project_path if project_path.exists() else None

  def list_projects(self) -> List[str]:
    """
    List all project directories.

    Returns:
        List[str]: List of project names
    """
    projects_dir = self.base_dir / "projects"
    if not projects_dir.exists():
      return []

    return [d.name for d in projects_dir.iterdir() if d.is_dir()]

  def get_disk_usage(self) -> Dict[str, Any]:
    """
    Get disk usage information for the work directory.

    Returns:
        Dict[str, Any]: Disk usage information
    """
    try:
      usage = shutil.disk_usage(self.base_dir)
      return {
          'total': usage.total,
          'used': usage.used,
          'free': usage.free,
          'base_dir_size': self._get_dir_size(self.base_dir)
      }
    except Exception as e:
      self.logger.error("Failed to get disk usage: %s", str(e))
      return {}

  def _get_dir_size(self, path: Path) -> int:
    """Get the total size of a directory."""
    total_size = 0
    try:
      for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
          filepath = os.path.join(dirpath, filename)
          try:
            total_size += os.path.getsize(filepath)
          except (OSError, FileNotFoundError):
            pass
    except Exception:
      pass
    return total_size
