"""
File Utility Functions.
"""

import logging
import os
import re
import shutil

from ossfuzz_py.core.data_models import FileType
from ossfuzz_py.utils.env_utils import EnvUtils

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.file_utils')

class FileUtils:
  """
  File Utility Functions (moved from original benchmark.py)
  """
  logger = logging.getLogger('ossfuzz_sdk.file_utils')

  @classmethod
  def get_file_type(cls, file_path: str) -> FileType:
    """
    Returns the file type based on the extension of file_path.

    Args:
        file_path: Path to the file

    Returns:
        FileType enum value

    Example:
        >>> get_file_type("test.c")
        <FileType.C: 'C'>
        >>> get_file_type("test.cpp")
        <FileType.CPP: 'C++'>
    """
    if file_path.endswith('.c'):
      return FileType.C
    cpp_extensions = ['.cc', '.cpp', '.cxx', '.c++', '.h', '.hpp']
    if any(file_path.endswith(ext) for ext in cpp_extensions):
      return FileType.CPP
    if file_path.endswith('.java'):
      return FileType.JAVA
    return FileType.NONE

  @classmethod
  def is_c_file(cls, file_path: str) -> bool:
    """
    Validates if file_path is a C file by its extension.

    Args:
        file_path: Path to check

    Returns:
        True if C file, False otherwise

    Example:
        >>> is_c_file("test.c")
        True
        >>> is_c_file("test.cpp")
        False
    """
    return FileUtils.get_file_type(file_path) == FileType.C

  @classmethod
  def is_cpp_file(cls, file_path: str) -> bool:
    """
    Validates if file_path is a C++ file by its extension.

    Args:
        file_path: Path to check

    Returns:
        True if C++ file, False otherwise

    Example:
        >>> is_cpp_file("test.cpp")
        True
        >>> is_cpp_file("test.c")
        False
    """
    return FileUtils.get_file_type(file_path) == FileType.CPP

  @classmethod
  def is_java_file(cls, file_path: str) -> bool:
    """
    Validates if file_path is a Java file by its extension.

    Args:
        file_path: Path to check

    Returns:
        True if Java file, False otherwise

    Example:
        >>> is_java_file("Test.java")
        True
        >>> is_java_file("test.c")
        False
    """
    return FileUtils.get_file_type(file_path) == FileType.JAVA

  @classmethod
  def rectify_docker_tag(cls, docker_tag: str) -> str:
    """Rectify Docker tag to be valid."""
    # Replace "::" and any character not \w, _, or . with "-".
    valid_docker_tag = re.sub(r'::', '-', docker_tag)
    valid_docker_tag = re.sub(r'[^\w_.]', '-', valid_docker_tag)
    # Docker fails with tags containing -_ or _-.
    valid_docker_tag = re.sub(r'[-_]{2,}', '-', valid_docker_tag)
    return valid_docker_tag

  @classmethod
  def create_ossfuzz_project(cls, benchmark_project: str,
                             generated_oss_fuzz_project: str) -> str:
    """Creates an OSS-Fuzz project by replicating an existing project."""
    oss_fuzz_dir = EnvUtils.get_oss_fuzz_dir()

    generated_project_path = os.path.join(oss_fuzz_dir, 'projects',
                                          generated_oss_fuzz_project)
    if os.path.exists(generated_project_path):
      logger.info('Project %s already exists.', generated_project_path)
      return generated_project_path

    oss_fuzz_project_path = os.path.join(oss_fuzz_dir, 'projects',
                                         benchmark_project)
    shutil.copytree(oss_fuzz_project_path, generated_project_path)
    return generated_project_path
