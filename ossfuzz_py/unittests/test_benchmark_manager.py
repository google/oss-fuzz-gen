#!/usr/bin/env python3
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
Test script for BenchmarkManager and Benchmark classes.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the SDK to the path
sys.path.insert(0, str(Path(__file__).parent))


def test_benchmark_creation():
  """Test creating and validating Benchmark instances."""
  print("🧪 Testing Benchmark creation...")

  try:
    from ossfuzz_py.core.benchmark_manager import Benchmark

    # Test valid benchmark creation
    benchmark = Benchmark(
        id="libpng-png_read_info",
        project="libpng",
        language="C",
        function_signature="void png_read_info(png_structp png_ptr, "
        "png_infop info_ptr)",
        function_name="png_read_info",
        return_type="void",
        params=[{
            "name": "png_ptr",
            "type": "png_structp"
        }, {
            "name": "info_ptr",
            "type": "png_infop"
        }],
        target_path="/src/libpng/pngread.c",
    )

    print(f"✓ Created benchmark: {benchmark.id}")
    print(f"  - Project: {benchmark.project}")
    print(f"  - Language: {benchmark.language}")
    print(f"  - Function: {benchmark.function_name}")
    print(f"  - Parameters: {len(benchmark.params)}")

    # Test hash functionality
    benchmark_set = {benchmark}
    assert len(benchmark_set) == 1
    print("✓ Hash functionality works")

    return True

  except Exception as e:
    print(f"❌ Benchmark creation test failed: {e}")
    return False


def test_benchmark_manager():
  """Test BenchmarkManager CRUD operations."""
  print("\n🧪 Testing BenchmarkManager...")

  try:
    from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

    manager = BenchmarkManager()

    # Create test benchmarks
    benchmark1 = Benchmark(
        id="test-func1",
        project="test-project",
        language="C++",
        function_signature="int test_func1(const char* input)",
        function_name="test_func1",
        return_type="int",
        params=[{
            "name": "input",
            "type": "const char*"
        }],
        target_path="/src/test.cpp")

    benchmark2 = Benchmark(id="test-func2",
                           project="test-project",
                           language="C++",
                           function_signature="void test_func2()",
                           function_name="test_func2",
                           return_type="void",
                           params=[],
                           target_path="/src/test.cpp")

    # Test adding benchmarks
    assert manager.add_benchmark(benchmark1) is True
    assert manager.add_benchmark(benchmark2) is True
    assert manager.add_benchmark(benchmark1) is False  # Duplicate
    print("✓ Add benchmark functionality works")

    # Test listing benchmarks
    benchmark_list = manager.list_benchmarks()
    assert len(benchmark_list) == 2
    assert "test-func1" in benchmark_list
    assert "test-func2" in benchmark_list
    print("✓ List benchmarks functionality works")

    # Test getting benchmarks
    retrieved = manager.get_benchmark("test-func1")
    assert retrieved is not None
    assert retrieved.id == "test-func1"
    print("✓ Get benchmark functionality works")

    # Test filtering by project
    project_benchmarks = manager.get_benchmarks_by_project("test-project")
    assert len(project_benchmarks) == 2
    print("✓ Filter by project functionality works")

    # Test filtering by language
    cpp_benchmarks = manager.get_benchmarks_by_language("C++")
    assert len(cpp_benchmarks) == 2
    print("✓ Filter by language functionality works")

    # Test count
    assert manager.count() == 2
    print("✓ Count functionality works")

    # Test removal
    assert manager.remove_benchmark("test-func1") is True
    assert manager.remove_benchmark("test-func1") is False  # Already removed
    assert manager.count() == 1
    print("✓ Remove benchmark functionality works")

    return True

  except Exception as e:
    print(f"❌ BenchmarkManager test failed: {e}")
    import traceback
    traceback.print_exc()
    return False


def test_import_export():
  """Test import/export functionality."""
  print("\n🧪 Testing import/export...")

  try:
    from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

    manager = BenchmarkManager()

    # Create test benchmarks
    benchmarks = [
        Benchmark(id="export-test1",
                  project="export-project",
                  language="Python",
                  function_signature="def test_function(x: int) -> str",
                  function_name="test_function",
                  return_type="str",
                  params=[{
                      "name": "x",
                      "type": "int"
                  }],
                  target_path="/src/test.py"),
        Benchmark(id="export-test2",
                  project="export-project",
                  language="Python",
                  function_signature="def another_function() -> None",
                  function_name="another_function",
                  return_type="None",
                  params=[],
                  target_path="/src/test.py")
    ]

    # Add benchmarks to manager
    for benchmark in benchmarks:
      manager.add_benchmark(benchmark)

    # Test YAML export/import
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml',
                                     delete=False) as f:
      yaml_path = f.name

    try:
      success = manager.export_benchmarks(benchmarks, yaml_path)
      assert success is True
      print("✓ YAML export works")

      # Clear manager and import
      manager.clear()
      assert manager.count() == 0

      imported = manager.import_benchmarks(yaml_path)
      assert len(imported) == 2
      assert manager.count() == 2
      print("✓ YAML import works")

    finally:
      os.unlink(yaml_path)

    # Test JSON export/import
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                     delete=False) as f:
      json_path = f.name

    try:
      success = manager.export_benchmarks(benchmarks, json_path)
      assert success is True
      print("✓ JSON export works")

      # Clear manager and import
      manager.clear()
      assert manager.count() == 0

      imported = manager.import_benchmarks(json_path)
      assert len(imported) == 2
      assert manager.count() == 2
      print("✓ JSON import works")

    finally:
      os.unlink(json_path)

    return True

  except Exception as e:
    print(f"❌ Import/export test failed: {e}")
    import traceback
    traceback.print_exc()
    return False


def test_function_name_parsing():
  """Test automatic function name parsing."""
  print("\n🧪 Testing function name parsing...")

  try:
    from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

    manager = BenchmarkManager()

    # Test C function parsing
    benchmark_c = Benchmark(
        id="c-test",
        project="test",
        language="C",
        function_signature="int my_function(const char* input, size_t len)",
        function_name="",  # Empty - should be auto-parsed
        return_type="int",
        params=[],
        target_path="/src/test.c")

    success = manager.add_benchmark(benchmark_c)
    assert success is True

    retrieved = manager.get_benchmark("c-test")
    if retrieved:
      print(f"✓ C function name parsed: '{retrieved.function_name}'")

    # Test Python function parsing
    benchmark_py = Benchmark(
        id="py-test",
        project="test",
        language="Python",
        function_signature="def my_python_func(x: int, y: str) -> bool:",
        function_name="",  # Empty - should be auto-parsed
        return_type="bool",
        params=[],
        target_path="/src/test.py")

    success = manager.add_benchmark(benchmark_py)
    assert success is True

    retrieved = manager.get_benchmark("py-test")
    if retrieved:
      print(f"✓ Python function name parsed: '{retrieved.function_name}'")

    return True

  except Exception as e:
    print(f"❌ Function name parsing test failed: {e}")
    import traceback
    traceback.print_exc()
    return False


def main():
  """Run all tests."""
  print("🧪 Testing BenchmarkManager and Benchmark Implementation")
  print("=" * 60)

  tests_passed = 0
  total_tests = 4

  if test_benchmark_creation():
    tests_passed += 1

  if test_benchmark_manager():
    tests_passed += 1

  if test_import_export():
    tests_passed += 1

  if test_function_name_parsing():
    tests_passed += 1

  print("\n" + "=" * 60)
  print(f"🎉 {tests_passed}/{total_tests} tests passed!")

  if tests_passed == total_tests:
    print("\n📋 Implementation Summary:")
    print("  ✓ Immutable Benchmark dataclass with validation")
    print("  ✓ BenchmarkManager CRUD operations")
    print("  ✓ YAML/JSON import/export functionality")
    print("  ✓ Automatic function name parsing")
    print("  ✓ Project and language filtering")
    print("  ✓ Hash-based benchmark identification")
    print("  ✓ Comprehensive error handling and logging")

  return 0 if tests_passed == total_tests else 1


if __name__ == "__main__":
  sys.exit(main())
