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
Encapsulates fuzz target details including source code management,
build script configuration, metadata, and dependencies.

This module aligns with the Writing Stage: Benchmark → FuzzTarget Source pattern
from the original oss-fuzz-gen design, where a Benchmark (metadata) is converted
into a FuzzTarget (source code + build script).
"""
from pathlib import Path
from typing import Any, Dict, List, Optional


class FuzzTarget:
  """
  Represents a single fuzz target with source code and build script.

  This class aligns with the original oss-fuzz-gen design where:
  - Benchmark contains metadata (what to fuzz)
  - FuzzTarget contains implementation (how to fuzz)

  The FuzzTarget stores both the source code content and build script content,
  not just file paths, following the pattern from results.py in oss-fuzz-gen.
  """

  def __init__(
      self,
      name: str,
      source_code: str,  # Actual source code content (not path)
      build_script: str,  # Actual build script content (not path)
      project_name: str,  # OSS-Fuzz project name
      language: str,  # Programming language
      function_signature: Optional[str] = None,
      # Function being fuzzed
      target_path: Optional[str] = None,  # Original target file path
      binary_name: Optional[str] = None,  # Expected binary name
      engine: str = 'libfuzzer',  # Fuzzing engine
      sanitizers: Optional[List[str]] = None,  # Sanitizers to use
      options: Optional[Dict[str, Any]] = None,  # Additional options
      dependencies: Optional[List[str]] = None  # Dependencies
  ):
    self.name = name
    self.source_code = source_code
    self.build_script = build_script
    self.project_name = project_name
    self.language = language
    self.function_signature = function_signature or ""
    self.target_path = target_path or ""
    self.binary_name = binary_name or name
    self.engine = engine
    self.sanitizers = sanitizers if sanitizers is not None else ['address']
    self.options = options if options is not None else {}
    self.dependencies = dependencies if dependencies is not None else []

    # Runtime attributes
    self.build_artifacts_path: Optional[str] = None

  def __repr__(self) -> str:
    return (f"FuzzTarget(name='{self.name}', project='{self.project_name}', "
            f"language='{self.language}')")

  def get_config(self) -> Dict[str, Any]:
    """Returns the configuration of the fuzz target as a dictionary."""
    return {
        'name':
            self.name,
        'source_code':
            self.source_code[:100] +
            "..." if len(self.source_code) > 100 else self.source_code,
        'build_script':
            self.build_script[:100] +
            "..." if len(self.build_script) > 100 else self.build_script,
        'project_name':
            self.project_name,
        'language':
            self.language,
        'function_signature':
            self.function_signature,
        'target_path':
            self.target_path,
        'binary_name':
            self.binary_name,
        'engine':
            self.engine,
        'sanitizers':
            self.sanitizers,
        'options':
            self.options,
        'dependencies':
            self.dependencies,
        'build_artifacts_path':
            self.build_artifacts_path
    }

  def set_build_artifacts_path(self, path: str) -> None:
    """Sets the path where build artifacts (e.g., the fuzzer executable) are
    stored."""
    self.build_artifacts_path = path

  # Fixme
  # !!!ONLY FOR TEST!!!
  # Below methods are for creating fuzz targets from benchmarks.
  def save_to_files(self, directory: Path) -> tuple[Path, Path]:
    """
    Save fuzz target source and build script to files.

    Args:
        directory: Directory to save files in

    Returns:
        Tuple of (source_file_path, build_script_path)
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    # Determine file extension based on language
    if self.language.lower() in ['c++', 'cpp']:
      ext = '.cc'
    elif self.language.lower() == 'c':
      ext = '.c'
    elif self.language.lower() == 'java':
      ext = '.java'
    elif self.language.lower() == 'python':
      ext = '.py'
    elif self.language.lower() == 'rust':
      ext = '.rs'
    else:
      ext = '.cc'  # Default to C++

    # Save source code
    source_path = directory / f"{self.name}{ext}"
    source_path.write_text(self.source_code)

    # Save build script
    build_path = directory / "build.sh"
    build_path.write_text(self.build_script)
    build_path.chmod(0o755)  # Make executable

    return source_path, build_path

  @classmethod
  def from_benchmark(cls, benchmark, source_code: str,
                     build_script: str) -> 'FuzzTarget':
    """
    Create a FuzzTarget from a Benchmark and generated source code.

    This method implements the Writing Stage: Benchmark → FuzzTarget Source
    pattern from the original oss-fuzz-gen design.

    Args:
        benchmark: Benchmark object with metadata
        source_code: Generated fuzz target source code
        build_script: Generated build script

    Returns:
        FuzzTarget instance
    """
    return cls(name=benchmark.target_name_,
               source_code=source_code,
               build_script=build_script,
               project_name=benchmark.project,
               language=benchmark.language,
               function_signature=benchmark.function_signature,
               target_path=benchmark.target_path,
               binary_name=benchmark.target_name or benchmark.target_name_)

  @classmethod
  def create_basic_template(cls, benchmark) -> 'FuzzTarget':
    """
    Create a basic fuzz target template from a benchmark.

    This generates a simple template that can be used as a starting point
    for more sophisticated fuzz target generation.

    Args:
        benchmark: Benchmark object with metadata

    Returns:
        FuzzTarget with basic template code
    """
    # Generate basic source code template
    if benchmark.language.lower() in ['c++', 'cpp', 'c']:
      source_code = cls._generate_c_cpp_template(benchmark)
    elif benchmark.language.lower() == 'java':
      source_code = cls._generate_java_template(benchmark)
    elif benchmark.language.lower() == 'python':
      source_code = cls._generate_python_template(benchmark)
    else:
      source_code = cls._generate_c_cpp_template(benchmark)  # Default

    # Generate basic build script
    build_script = cls._generate_build_script_template(benchmark)

    return cls.from_benchmark(benchmark, source_code, build_script)

  @staticmethod
  def _generate_c_cpp_template(benchmark) -> str:
    """Generate a basic C/C++ fuzz target template."""
    include_header = \
      f'#include "{benchmark.target_path}"' if benchmark.target_path else ""

    template = f"""#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
{include_header}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 4) {{
        return 0;
    }}

    // TODO: Parse input data and call {benchmark.function_signature}
    // Example:
    // {benchmark.function_name}(/* parameters from data */);

    return 0;
}}
"""
    return template.strip()

  @staticmethod
  def _generate_java_template(benchmark) -> str:
    """Generate a basic Java fuzz target template."""
    template = f"""import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class {benchmark.target_name_} {{
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        // TODO: Parse input data and call {benchmark.function_signature}
        // Example:
        // {benchmark.function_name}(data.consumeString(100));
    }}
}}
"""
    return template.strip()

  @staticmethod
  def _generate_python_template(benchmark) -> str:
    """Generate a basic Python fuzz target template."""
    template = f"""import atheris
import sys

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # TODO: Parse input data and call {benchmark.function_signature}
    # Example:
    # {benchmark.function_name}(fdp.ConsumeString(100))

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
"""
    return template.strip()

  @staticmethod
  def _generate_build_script_template(benchmark) -> str:
    """Generate a basic build script template."""
    if benchmark.language.lower() in ['c++', 'cpp', 'c']:
      return f"""#!/bin/bash -eu

# Build script for {benchmark.project} fuzz target
$CXX $CXXFLAGS -c {benchmark.target_name_}.cc -o {benchmark.target_name_}.o
$CXX $CXXFLAGS {benchmark.target_name_}.o -o $OUT/{benchmark.target_name_} $LIB_FUZZING_ENGINE
"""
    if benchmark.language.lower() == 'java':
      return f"""#!/bin/bash -eu

# Build script for {benchmark.project} Java fuzz target
$JAVA_HOME/bin/javac -cp $JAZZER_API_PATH {benchmark.target_name_}.java
$JAVA_HOME/bin/jar cf $OUT/{benchmark.target_name_}.jar {benchmark.target_name_}.class
"""
    if benchmark.language.lower() == 'python':
      return f"""#!/bin/bash -eu

# Build script for {benchmark.project} Python fuzz target
cp {benchmark.target_name_}.py $OUT/
"""
    # Default C++ build script
    return f"""#!/bin/bash -eu

# Build script for {benchmark.project} fuzz target
$CXX $CXXFLAGS -c {benchmark.target_name_}.cc -o {benchmark.target_name_}.o
$CXX $CXXFLAGS {benchmark.target_name_}.o -o $OUT/{benchmark.target_name_} $LIB_FUZZING_ENGINE
"""
