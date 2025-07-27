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

import os
import logger

from agent_tests.base_agent_test import BaseAgentTest
from results import AnalysisResult, BuildResult, CrashResult, RunResult


class ExecutionStageTest(BaseAgentTest):
  """Test for the CrashAnalyzer agent."""

  def get_fuzz_target_and_build_script_paths(
      self, additional_files_path: str) -> tuple[str, str]:
    """Gets the file paths ending with .fuzz_target and .build_script from additional files path.

    Args:
        additional_files_path: Directory path containing the files

    Returns:
        tuple: (fuzz_target_path, build_script_path)

    Raises:
        FileNotFoundError: If fuzz_target file is not found
        ValueError: If multiple files with same extension are found
    """
    if not os.path.exists(additional_files_path):
      raise FileNotFoundError(
          f"Additional files path does not exist: {additional_files_path}")

    fuzz_target_files = []
    build_script_files = []

    # Walk through the directory to find files with specified extensions
    for root, dirs, files in os.walk(additional_files_path):
      for file in files:
        file_path = os.path.join(root, file)
        if file.endswith('.fuzz_target'):
          fuzz_target_files.append(file_path)
        elif file.endswith('.build_script'):
          build_script_files.append(file_path)

    # Check for fuzz_target file
    if not fuzz_target_files:
      raise FileNotFoundError(
          f"No .fuzz_target file found in {additional_files_path}")
    elif len(fuzz_target_files) > 1:
      raise ValueError(
          f"Multiple .fuzz_target files found: {fuzz_target_files}")

    fuzz_target_path = fuzz_target_files[0]

    # Build script is optional, so we don't raise error if not found
    build_script_path = build_script_files[0] if build_script_files else ''

    if len(build_script_files) > 1:
      raise ValueError(
          f"Multiple .build_script files found: {build_script_files}")

    return fuzz_target_path, build_script_path

  def setup_initial_result_list(self, benchmark, prompt):
    """Sets up the initial result list for the CrashAnalyzer agent test."""

    # Extract the fuzz target and build script from the self.args.additional_files_path
    if not self.args.additional_files_path:
      raise ValueError("Additional files path is not provided.")

    # Get the file ending with .fuzz_target and .build_script from
    fuzz_target_path, build_script_path = self.get_fuzz_target_and_build_script_paths(
        self.args.additional_files_path)

    with open(fuzz_target_path, 'r') as file:
      fuzz_target_source = file.read()
    if os.path.exists(build_script_path) and os.path.getsize(
        build_script_path) > 0:
      with open(build_script_path, 'r') as file:
        build_script_source = file.read()
    else:
      build_script_source = ''

    fuzz_target_path = os.path.join(self.args.work_dirs.fuzz_targets,
                                    f'{self.trial:02d}.fuzz_target')
    with open(fuzz_target_path, 'w') as file:
      file.write(fuzz_target_source)
    build_script_path = os.path.join(self.args.work_dirs.fuzz_targets,
                                    f'{self.trial:02d}.build_script')
    with open(build_script_path, 'w') as file:
      file.write(build_script_source)

    build_result = BuildResult(benchmark=benchmark,
                           trial=self.trial,
                           work_dirs=self.args.work_dirs,
                           author=None,
                           chat_history={},
                           compiles=True,
                           binary_exists=True,
                           is_function_referenced=True,
                           fuzz_target_source=fuzz_target_source,
                           build_script_source=build_script_source,)

    return [build_result]
