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
File Utility Functions.
"""

import logging
import re

from ossfuzz_py.core.data_models import FileType


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
