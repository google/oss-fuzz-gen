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
Benchmark Management System for the OSS-Fuzz SDK.

This module provides the Benchmark and BenchmarkManager classes for managing
benchmark metadata and CRUD operations. It supports YAML/JSON import/export
and integrates with the FunctionExtractor for parsing function signatures.

The Benchmark class is a pure data holder (frozen dataclass) containing all
benchmark metadata. The BenchmarkManager handles all I/O, validation, and CRUD
operations for benchmarks.
"""

import hashlib
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ossfuzz_py.core.data_models import FileType
from ossfuzz_py.errors import BenchmarkError, BenchmarkValidationError
from ossfuzz_py.utils.file_utils import FileUtils

# Configure module logger
logger = logging.getLogger('ossfuzz_sdk.benchmark_manager')


@dataclass(frozen=True)
class Benchmark:
  """
  Immutable data class that stores metadata
  for a single benchmark/function-under-test.

  This is a pure data holder containing all benchmark metadata for fuzzing,
  including function signature information, project details, and optional
  configuration flags. All business logic is handled by BenchmarkManager.

  Fields are identical to the original benchmark.py implementation to ensure
  compatibility with existing benchmark files.
  """

  # Core identification fields (required)
  project: str = field(metadata={"description": "OSS-Fuzz project name"})
  language: str = field(
      metadata={"description": "Primary language (C/C++/Rust/   )"})
  function_signature: str = field(
      metadata={"description": "Full function signature string"})
  function_name: str = field(metadata={"description": "Parsed function name"})
  return_type: str = field(metadata={"description": "Function return type"})
  target_path: str = field(
      metadata={"description": "Path to header/source file"})

  # Auto-computed unique identifier (computed from project + signature)
  id: str = field(
      default='',
      metadata={
          "description": "Unique benchmark identifier (auto-computed) "
                         "and will be overwritten if manually set"
      })

  # Optional fields with defaults
  params: List[Dict[str, str]] = field(
      default_factory=list,
      metadata={"description": "List of {name, type} parameter dicts"})
  target_name_: Optional[str] = field(
      default=None,
      metadata={
          "description":
              "The binary name is set by the the build script in OSS-Fuzz"
      })
  use_project_examples: bool = field(
      default=True, metadata={"description": "Whether to use project examples"})
  use_context: bool = field(
      default=False,
      metadata={"description": "Whether to use context information"})
  commit: Optional[str] = field(
      default=None, metadata={"description": "OSS-Fuzz project commit hash"})
  test_file_path: str = field(
      default='',
      metadata={"description": "Path to test file (for test-based benchmarks)"})
  function_dict: Optional[Dict[str, Any]] = field(
      default=None,
      metadata={"description": "Original function dictionary from YAML"})

  def __post_init__(self):
    """Compute unique ID based on the project name and function signature."""
    # Create hash input from the project and signature
    hash_input = f"{self.project}-{self.function_signature}"
    # Use SHA256 hash and convert to 16 characters
    hash_digest = self._hash_sha256(hash_input)

    # Use object.__setattr__ since this is a frozen dataclass
    object.__setattr__(self, 'id', hash_digest)

  def _hash_sha256(self, input_string: str) -> str:
    """Generate exactly 16 alphanumeric characters using SHA256 → Base36."""
    # Get SHA256 hash (256 bits)
    hash_bytes = hashlib.sha256(input_string.encode('utf-8')).digest()

    # Take 11 bytes (88 bits) - just enough for 16 base36 chars
    # We need 82.7 bits minimum, 88 bits gives us perfect coverage
    # Thanks to cryptographic hash properties:
    # taking the first 88 bits out of 256 bits
    # does NOT affect collision probability
    hash_int = int.from_bytes(hash_bytes[:11], byteorder='big')

    # Convert to base36 (0-9, a-z)
    base36_chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""

    for _ in range(16):
      result = base36_chars[hash_int % 36] + result
      hash_int //= 36

    return result

  def __hash__(self) -> int:
    """Hash based on benchmark id for use in sets and as dict keys."""
    return hash(self.id)

  @property
  def target_name(self) -> str:
    """
    Returns target_name if defined, otherwise basename of target_path.

    Example:
        >>> b = Benchmark(id="test", project="test", language="c++",
                          function_signature="", function_name="",
                          return_type="",
                          target_path="/src/libraw_fuzzer.cc",
                          target_name="libraw_fuzzer")
        >>> b.target_name
        'libraw_fuzzer'
        >>> b2 = Benchmark(id="test2", project="test", language="c++",
                           function_signature="", function_name="",
                           return_type="",
                           target_path="/src/libraw_fuzzer.cc")
        >>> b2.target_name
        '/src/libraw_fuzzer.cc'
    """
    return (self.target_name_ or
            os.path.splitext(os.path.basename(self.target_path))[0])

  @property
  def file_type(self) -> FileType:
    """
    Returns the file type of the benchmark target.

    Example:
        >>> b = Benchmark(id="test", project="test", language="c++",
                          function_signature="", function_name="",
                          return_type="",
                          target_path="/src/test.cc")
        >>> b.file_type
        <FileType.CPP: 'C++'>
    """
    return FileUtils.get_file_type(self.target_path)

  @property
  def is_c_target(self) -> bool:
    """Validates if the target file is written in C."""
    return self.file_type.value.lower() == 'c'

  @property
  def is_cpp_target(self) -> bool:
    """Validates if the target file is written in C++."""
    return self.file_type.value.lower() == 'c++'

  @property
  def is_java_target(self) -> bool:
    """Validates if the target file is written in Java."""
    return self.file_type.value.lower() == 'java'

  @property
  def is_c_project(self) -> bool:
    """Validates if the project language is C."""
    return self.language.lower() == 'c'

  @property
  def is_cpp_project(self) -> bool:
    """Validates if the project language is C++."""
    return self.language.lower() == 'c++'

  @property
  def is_java_project(self) -> bool:
    """Validates if the project language is Java/JVM."""
    return self.language.lower() == 'jvm'

  @property
  def needs_extern(self) -> bool:
    """Checks if it is C++ fuzz target for a C project, which needs `extern`."""
    return self.is_cpp_target and self.is_c_project


class BenchmarkManager:
  """
  CRUD service for benchmarks with ordered storage
  and import/export capabilities.

  This class manages a collection of benchmarks with support
  for adding, retrieving, listing, and importing/exporting benchmarks.
  All business logic for benchmarks is handled here,
  including YAML/JSON serialization, validation, and helper methods.

  The manager supports both function-based and test-file-based benchmarks,
  and can round-trip import/export all benchmark files
  in oss-fuzz-gen/benchmark-sets.

  Example:
      >>> manager = BenchmarkManager()
      >>> benchmarks = manager.import_benchmarks("path/to/benchmark.yaml")
      >>> success = manager.add_benchmark(benchmarks[0])
      >>> retrieved = manager.get_benchmark("benchmark-id")
      >>> manager.export_benchmarks(benchmarks, "output.yaml")
  """

  def __init__(self):
    """Initialize the benchmark manager with empty storage."""
    self._benchmarks: OrderedDict[str, Benchmark] = OrderedDict()
    self.logger = logger

    self.logger.debug("Initialized BenchmarkManager")

  def get_benchmark(self, name: str) -> Optional[Benchmark]:
    """
    Retrieve a benchmark by ID.

    Args:
        name: Benchmark ID to retrieve

    Returns:
        Benchmark instance if found, None otherwise
    """
    benchmark = self._benchmarks.get(name)
    if benchmark:
      self.logger.debug("Retrieved benchmark: %s", name)
    else:
      self.logger.debug("Benchmark not found: %s", name)
    return benchmark

  def list_benchmarks(self) -> List[str]:
    """
    List all benchmark IDs.

    Returns:
        List of benchmark IDs in insertion order
    """
    benchmark_list = list(self._benchmarks.keys())
    self.logger.debug("Listed %d benchmarks", len(benchmark_list))
    return benchmark_list

  def add_benchmark(self, benchmark: Benchmark) -> bool:
    """
    Add a benchmark to the collection.

    Args:
        benchmark: Benchmark instance to add

    Returns:
        True if added successfully, False if duplicate

    Raises:
        BenchmarkValidationError: If benchmark is invalid
    """
    if not isinstance(benchmark, Benchmark):
      raise BenchmarkValidationError("Expected Benchmark instance")

    # Validate required fields
    self._validate_benchmark(benchmark)

    if benchmark.id in self._benchmarks:
      self.logger.warning("Benchmark already exists: %s", benchmark.id)
      return False

    self._benchmarks[benchmark.id] = benchmark
    self.logger.info("Added benchmark: %s", benchmark.id)
    return True

  def import_benchmarks(self, path: str) -> List[Benchmark]:
    """
    Import benchmarks from YAML or JSON file.

    Supports both function-based and test-file-based benchmarks from
    oss-fuzz-gen/benchmark-sets format.

    Args:
        path: Path to file (extension determines format)

    Returns:
        List of imported benchmarks

    Raises:
        BenchmarkError: If import fails

    Example:
        >>> manager = BenchmarkManager()
        >>> benchmarks = manager.import_benchmarks("libpng.yaml")
        >>> len(benchmarks) > 0
        True
    """
    file_path = Path(path)
    if not file_path.exists():
      raise BenchmarkError(f"File not found: {path}")

    try:
      extension = file_path.suffix.lower()

      if extension in ['.yaml', '.yml']:
        benchmarks = self._import_from_yaml(file_path)
      elif extension == '.json':
        benchmarks = self._import_from_json(file_path)
      else:
        raise BenchmarkError(f"Unsupported file format: {extension}")

      # Add imported benchmarks to collection
      imported_count = 0
      for benchmark in benchmarks:
        if self.add_benchmark(benchmark):
          imported_count += 1

      self.logger.info("Imported %d/%d benchmarks from %s", imported_count,
                       len(benchmarks), path)
      return benchmarks

    except Exception as e:
      raise BenchmarkError(f"Failed to import benchmarks: {str(e)}")

  def export_benchmarks(self,
                        benchmarks: List[Benchmark],
                        path: str,
                        file_format: str = "yaml") -> bool:
    """
    Export benchmarks to directory, grouped by project.

    Groups benchmarks by (project, language, target_path, target_name)
    and exports each project to a separate file named {project}.{format}
    in the specified directory.

    Args:
        benchmarks: List of benchmarks to export
        path: Output directory path (must be a directory)
        file_format: Export format, either "yaml" or "json"

    Returns:
        True if export is successful

    Raises:
        BenchmarkError: If export fails, path is not a directory,
        or format is invalid

    Example:
        >>> manager = BenchmarkManager()
        >>> benchmarks = [benchmark1, benchmark2]
        >>> success = manager.export_benchmarks(benchmarks,
            "/output/dir", "yaml")
        >>> success
        True
    """
    if not benchmarks:
      raise BenchmarkError("No benchmarks to export")

    # Validate file format
    if file_format not in ["yaml", "json"]:
      raise BenchmarkError(
          f"Unsupported file format: {file_format}. Must be 'yaml' or 'json'")

    # Validate and create directory
    dir_path = Path(path)
    if dir_path.exists() and not dir_path.is_dir():
      raise BenchmarkError(f"Path exists but is not a directory: {path}")

    try:
      dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
      raise BenchmarkError(f"Failed to create directory {path}: {str(e)}")

    try:
      # Group benchmarks by project
      project_groups = self._group_benchmarks_by_project(benchmarks)

      exported_files = 0
      total_exported = 0

      for project_name, project_benchmarks in project_groups.items():
        # Create safe filename
        safe_filename = self._make_safe_filename(project_name)
        file_path = dir_path / f"{safe_filename}.{file_format}"

        # Export based on format
        if file_format == "yaml":
          self._export_to_yaml(project_benchmarks, file_path)
        else:  # json
          self._export_to_json(project_benchmarks, file_path)

        exported_files += 1
        total_exported += len(project_benchmarks)
        self.logger.debug("Exported %d benchmarks for project '%s' to %s",
                          len(project_benchmarks), project_name, file_path)

      self.logger.info("Exported %d benchmarks across %d files to directory %s",
                       total_exported, exported_files, path)
      return True

    except Exception as e:
      raise BenchmarkError(f"Failed to export benchmarks: {str(e)}")

  def _group_benchmarks_by_project(
      self, benchmarks: List[Benchmark]) -> Dict[str, List[Benchmark]]:
    """
    Group benchmarks by project name.

    All benchmarks with the same project name will be grouped together,
    regardless of their language, target_path, or target_name differences.

    Args:
        benchmarks: List of benchmarks to group

    Returns:
        Dictionary mapping project names to lists of benchmarks
    """
    project_groups: Dict[str, List[Benchmark]] = {}

    for benchmark in benchmarks:
      project_name = benchmark.project
      if project_name not in project_groups:
        project_groups[project_name] = []
      project_groups[project_name].append(benchmark)

    return project_groups

  def _make_safe_filename(self, filename: str) -> str:
    """
    Make a filename safe for filesystem use.

    Replaces illegal characters with underscores and handles edge cases.

    Args:
        filename: Original filename

    Returns:
        Safe filename for filesystem use
    """
    import re

    # Replace illegal characters with underscores
    # Illegal chars: / \ : * ? " < > | and whitespace
    safe_name = re.sub(r'[/\\:*?"<>|\s]+', '_', filename)

    # Remove leading/trailing underscores and dots
    safe_name = safe_name.strip('_.')

    # Ensure it's not empty
    if not safe_name:
      safe_name = "unnamed_project"

    # Limit length to reasonable filesystem limits
    if len(safe_name) > 100:
      safe_name = safe_name[:100]

    return safe_name

  def _validate_benchmark(self, benchmark: Benchmark) -> None:
    """
    Validate benchmark data.

    Args:
        benchmark: Benchmark to validate

    Raises:
        BenchmarkValidationError: If validation fails
    """
    if not benchmark.id:
      raise BenchmarkValidationError("Benchmark ID is required")
    if not benchmark.project:
      raise BenchmarkValidationError("Project name is required")
    if not benchmark.language:
      raise BenchmarkValidationError("Language is required")
    if not benchmark.target_path:
      raise BenchmarkValidationError("Target path is required")

  def _import_from_yaml(self, file_path: Path) -> List[Benchmark]:
    """
    Import benchmarks from YAML file using oss-fuzz-gen format.

    Handles both function-based and test-file-based benchmarks.
    """
    with open(file_path, 'r') as f:
      data = yaml.safe_load(f)

    if not data:
      return []

    benchmarks = []

    # Extract common fields
    project_name = data.get('project', '')
    language = data.get('language', '')
    target_path = data.get('target_path', '')
    target_name = data.get('target_name', '')
    commit = data.get('commit')
    use_context = data.get('use_context', False)
    use_project_examples = data.get('use_project_examples', True)

    # Handle test files
    test_files = data.get('test_files', [])
    if test_files:
      for test_file in test_files:
        test_file_path = test_file.get('test_file_path', '')
        # For test files, use the test file path as the signature for ID
        # generation
        normalized_test_path = (test_file_path.replace('/', '_').replace(
            '.', '_').replace('-', '_'))

        benchmarks.append(
            Benchmark(project=project_name,
                      language=language,
                      function_signature=normalized_test_path,
                      function_name='',
                      return_type='',
                      params=[],
                      target_path=target_path,
                      target_name_=target_name,
                      use_project_examples=use_project_examples,
                      use_context=use_context,
                      commit=commit,
                      test_file_path=test_file_path))

    # Handle functions
    functions = data.get('functions', [])
    if functions:
      for function in functions:
        # ID will be auto-computed from project and function signature
        benchmarks.append(
            Benchmark(project=project_name,
                      language=language,
                      function_signature=function.get('signature', ''),
                      function_name=function.get('name', ''),
                      return_type=function.get('return_type', ''),
                      params=function.get('params', []),
                      target_path=target_path,
                      target_name_=target_name,
                      use_project_examples=use_project_examples,
                      use_context=use_context,
                      commit=commit,
                      function_dict=function))

    return benchmarks

  def _import_from_json(self, file_path: Path) -> List[Benchmark]:
    """
    Import benchmarks from JSON file using oss-fuzz-gen format.

    Uses same logic as YAML import but with JSON parsing.
    """
    with open(file_path, 'r') as f:
      data = json.load(f)

    if not data:
      return []

    # Reuse YAML import logic by temporarily writing to YAML
    # This ensures consistent parsing behavior
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml',
                                     delete=False) as temp_file:
      yaml.dump(data, temp_file, default_flow_style=False)
      temp_path = Path(temp_file.name)

    try:
      return self._import_from_yaml(temp_path)
    finally:
      temp_path.unlink()  # Clean up temporary file

  def _export_to_yaml(self, benchmarks: List[Benchmark],
                      file_path: Path) -> None:
    """
    Export benchmarks to YAML file in oss-fuzz-gen format.

    Maintains compatibility with original benchmark.py to_yaml format.
    """
    # Create parent directory if it doesn't exist
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if not benchmarks:
      return

    # Use first benchmark for common fields
    first_benchmark = benchmarks[0]

    # Define custom representer for quoting strings (from original)
    def quoted_string_presenter(dumper, data):
      if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
      return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')

    yaml.add_representer(str, quoted_string_presenter)

    result: dict[str, Any] = {
        'project': first_benchmark.project,
        'language': first_benchmark.language,
        'target_path': first_benchmark.target_path,
        'target_name': first_benchmark.target_name or '',
    }

    # Add optional fields if present
    if first_benchmark.commit:
      result['commit'] = first_benchmark.commit

    # Separate test files and functions
    test_files = []
    functions = []

    for benchmark in benchmarks:
      if benchmark.test_file_path:
        test_files.append({'test_file_path': benchmark.test_file_path})
      else:
        functions.append({
            'id': benchmark.id,
            'signature': benchmark.function_signature,
            'name': benchmark.function_name,
            'return_type': benchmark.return_type,
            'params': benchmark.params
        })

    if test_files:
      result['test_files'] = test_files
    if functions:
      result['functions'] = functions

    with open(file_path, 'w') as f:
      yaml.dump(result, f, default_flow_style=False, width=1000000)

  def _export_to_json(self, benchmarks: List[Benchmark],
                      file_path: Path) -> None:
    """
    Export benchmarks to JSON file in oss-fuzz-gen format.

    Uses same structure as YAML export but in JSON format.
    """
    # Create parent directory if it doesn't exist
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if not benchmarks:
      return

    # Use first benchmark for common fields
    first_benchmark = benchmarks[0]

    result: dict[str, Any] = {
        'project': first_benchmark.project,
        'language': first_benchmark.language,
        'target_path': first_benchmark.target_path,
        'target_name': first_benchmark.target_name or '',
    }

    # Add optional fields if present
    if first_benchmark.commit:
      result['commit'] = first_benchmark.commit

    # Separate test files and functions
    test_files = []
    functions = []

    for benchmark in benchmarks:
      if benchmark.test_file_path:
        test_files.append({'test_file_path': benchmark.test_file_path})
      else:
        functions.append({
            'id': benchmark.id,
            'signature': benchmark.function_signature,
            'name': benchmark.function_name,
            'return_type': benchmark.return_type,
            'params': benchmark.params
        })

    if test_files:
      result['test_files'] = test_files
    if functions:
      result['functions'] = functions

    with open(file_path, 'w') as f:
      json.dump(result, f, indent=2, sort_keys=False)

  def count(self) -> int:
    """
    Get the number of benchmarks in the collection.

    Returns:
        Number of benchmarks
    """
    return len(self._benchmarks)

  def clear(self) -> None:
    """Clear all benchmarks from the collection."""
    count = len(self._benchmarks)
    self._benchmarks.clear()
    self.logger.info("Cleared %d benchmarks", count)

  def remove_benchmark(self, benchmark_id: str) -> bool:
    """
    Remove a benchmark by ID.

    Args:
        benchmark_id: ID of benchmark to remove

    Returns:
        True if removed, False if not found
    """
    if benchmark_id in self._benchmarks:
      del self._benchmarks[benchmark_id]
      self.logger.info("Removed benchmark: %s", benchmark_id)
      return True
    self.logger.debug("Benchmark not found for removal: %s", benchmark_id)
    return False

  def get_benchmarks_by_project(self, project: str) -> List[Benchmark]:
    """
    Get all benchmarks for a specific project.

    Args:
        project: Project name

    Returns:
        List of benchmarks for the project
    """
    benchmarks = [b for b in self._benchmarks.values() if b.project == project]
    self.logger.debug("Found %d benchmarks for project: %s", len(benchmarks),
                      project)
    return benchmarks

  def get_benchmarks_by_language(self, language: str) -> List[Benchmark]:
    """
    Get all benchmarks for a specific language.

    Args:
        language: Programming language

    Returns:
        List of benchmarks for the language
    """
    benchmarks = [
        b for b in self._benchmarks.values()
        if b.language.lower() == language.lower()
    ]
    self.logger.debug("Found %d benchmarks for language: %s", len(benchmarks),
                      language)
    return benchmarks
