# Copyright 2026 Google LLC
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
"""Tests for benchmark YAML loading."""

import os
import tempfile
import unittest

from experiment.benchmark import Benchmark


class BenchmarkTest(unittest.TestCase):
  """Tests Benchmark construction from YAML."""

  def test_from_yaml_accepts_project_level_fix_build_benchmark(self):
    """Accepts project-level metadata for a fix-build benchmark."""
    content = """
project: zlib
language: c
fuzzing_build_error_log: https://example.com/build-log.txt
software_sha: abc123
engine: libfuzzer
sanitizer: address
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml',
                                     delete=False) as temp_file:
      temp_file.write(content)
      temp_path = temp_file.name

    try:
      benchmarks = Benchmark.from_yaml(temp_path)
    finally:
      os.remove(temp_path)

    self.assertEqual(len(benchmarks), 1)
    benchmark = benchmarks[0]
    self.assertEqual(benchmark.id, 'zlib')
    self.assertEqual(benchmark.project, 'zlib')
    self.assertEqual(benchmark.language, 'c')
    self.assertEqual(benchmark.target_path, '')
    self.assertEqual(benchmark.function_name, '')
    self.assertEqual(benchmark.metadata['software_sha'], 'abc123')
    self.assertEqual(benchmark.metadata['engine'], 'libfuzzer')


if __name__ == '__main__':
  unittest.main()
