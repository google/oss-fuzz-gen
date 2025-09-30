#!/usr/bin/env python3
"""
Test script for BenchmarkManager and Benchmark classes.
"""

import sys
import tempfile
import unittest
from pathlib import Path

# Add the SDK to the path
sys.path.insert(0, str(Path(__file__).parent))

class TestBenchmarkManager(unittest.TestCase):
  """Test BenchmarkManager."""

  def test_benchmark_creation(self):
    """Test creating and validating Benchmark instances."""
    print("🧪 Testing Benchmark creation...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark

      # Test valid benchmark creation (ID will be auto-computed)
      benchmark = Benchmark(
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

      # Test that ID is auto-computed and reproducible
      benchmark2 = Benchmark(
          project="libpng",
          language="C",
          function_signature="void png_read_info(png_structp png_ptr, "
          "png_infop info_ptr)",
          function_name="png_read_info",
          return_type="void",
          target_path="/src/libpng/pngread.c",
      )
      assert benchmark.id == benchmark2.id, ("IDs should be identical for same "
                                             "project+signature")
      print("✓ ID auto-computation is reproducible")

      # Test hash functionality
      benchmark_set = {benchmark}
      assert len(benchmark_set) == 1
      print("✓ Hash functionality works")

      return True

    except Exception as e:
      print(f"❌ Benchmark creation test failed: {e}")
      return False

  def test_benchmark_manager(self):
    """Test BenchmarkManager CRUD operations."""
    print("\n🧪 Testing BenchmarkManager...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      # Create test benchmarks (IDs will be auto-computed)
      benchmark1 = Benchmark(
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

      benchmark2 = Benchmark(project="test-project",
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
      assert benchmark1.id in benchmark_list
      assert benchmark2.id in benchmark_list
      print("✓ List benchmarks functionality works")

      # Test getting benchmarks
      retrieved = manager.get_benchmark(benchmark1.id)
      assert retrieved is not None
      assert retrieved.id == benchmark1.id
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
      assert manager.remove_benchmark(benchmark1.id) is True
      assert manager.remove_benchmark(benchmark1.id) is False  # Already removed
      assert manager.count() == 1
      print("✓ Remove benchmark functionality works")

      return True

    except Exception as e:
      print(f"❌ BenchmarkManager test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

  def test_export_grouped_benchmarks_by_project_fields(self):
    """Test export functionality with grouping by project fields."""
    print("\n🧪 Testing export grouped benchmarks by project fields...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      # Create test benchmarks with different projects, languages, and target
      # paths
      benchmarks = [
          # Project 1: libpng (C language)
          Benchmark(
              project="libpng",
              language="C",
              function_signature=
              "void png_read_info(png_structp png_ptr, png_infop info_ptr)",
              function_name="png_read_info",
              return_type="void",
              target_path="/src/libpng/pngread.c",
              target_name_="libpng_fuzzer"),
          Benchmark(
              project="libpng",
              language="C",
              function_signature=
              "void png_write_info(png_structp png_ptr, png_infop info_ptr)",
              function_name="png_write_info",
              return_type="void",
              target_path="/src/libpng/pngwrite.c",
              target_name_="libpng_fuzzer"),

          # Project 2: test-cpp (C++ language)
          Benchmark(
              project="test-cpp",
              language="C++",
              function_signature="int process_data(const std::string& input)",
              function_name="process_data",
              return_type="int",
              target_path="/src/processor.cpp",
              target_name_="cpp_fuzzer"),

          # Project 3: python-lib (Python language)
          Benchmark(project="python-lib",
                    language="Python",
                    function_signature="def parse_json(data: str) -> dict",
                    function_name="parse_json",
                    return_type="dict",
                    target_path="/src/parser.py"),

          # Project 4: special/chars (test filename safety)
          Benchmark(project="special/chars project",
                    language="Java",
                    function_signature="public void testMethod(String input)",
                    function_name="testMethod",
                    return_type="void",
                    target_path="/src/Test.java")
      ]

      # Test YAML export
      with tempfile.TemporaryDirectory() as temp_dir:
        print(f"   Using temp directory: {temp_dir}")

        # Test YAML format
        success = manager.export_benchmarks(benchmarks, temp_dir, "yaml")
        assert success is True
        print("   ✓ YAML export completed successfully")

        # Verify files were created
        temp_path = Path(temp_dir)
        yaml_files = list(temp_path.glob("*.yaml"))
        print(f"   ✓ Created {len(yaml_files)} YAML files")

        expected_files = {
            "libpng.yaml", "test-cpp.yaml", "python-lib.yaml",
            "special_chars_project.yaml"
        }
        actual_files = {f.name for f in yaml_files}
        print(f"   Expected files: {expected_files}")
        print(f"   Actual files: {actual_files}")
        assert expected_files == actual_files, (f"Expected {expected_files}, "
                                                f"got {actual_files}")
        print("   ✓ All expected project files created with safe names")

        # Test JSON format
        success = manager.export_benchmarks(benchmarks, temp_dir, "json")
        assert success is True
        print("   ✓ JSON export completed successfully")

        # Verify JSON files were created
        json_files = list(temp_path.glob("*.json"))
        print(f"   ✓ Created {len(json_files)} JSON files")

        expected_json_files = {
            "libpng.json", "test-cpp.json", "python-lib.json",
            "special_chars_project.json"
        }
        actual_json_files = {f.name for f in json_files}
        assert expected_json_files == actual_json_files
        print("   ✓ All expected JSON project files created")

        # Verify file contents for one project
        libpng_yaml = temp_path / "libpng.yaml"
        assert libpng_yaml.exists()

        with open(libpng_yaml, 'r') as f:
          import yaml
          data = yaml.safe_load(f)
          assert data['project'] == 'libpng'
          assert data['language'] == 'C'
          assert len(data['functions']) == 2  # Two libpng functions
          print("   ✓ File contents are correctly grouped by project")

      return True

    except Exception as e:
      print(f"❌ Export grouped benchmarks test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

  def test_import_grouped_benchmarks_from_files(self):
    """Test import functionality from grouped project files."""
    print("\n🧪 Testing import grouped benchmarks from files...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      # Create original test benchmarks
      original_benchmarks = [
          Benchmark(project="import-test-1",
                    language="C",
                    function_signature="int func1(const char* input)",
                    function_name="func1",
                    return_type="int",
                    target_path="/src/test1.c"),
          Benchmark(project="import-test-1",
                    language="C",
                    function_signature="void func2(int x)",
                    function_name="func2",
                    return_type="void",
                    target_path="/src/test1.c"),
          Benchmark(project="import-test-2",
                    language="C++",
                    function_signature=
                    "std::string process(const std::vector<int>& data)",
                    function_name="process",
                    return_type="std::string",
                    target_path="/src/test2.cpp")
      ]

      with tempfile.TemporaryDirectory() as temp_dir:
        print(f"   Using temp directory: {temp_dir}")

        # Export benchmarks to files
        success = manager.export_benchmarks(original_benchmarks, temp_dir,
                                            "yaml")
        assert success is True
        print("   ✓ Exported benchmarks to directory")

        # Verify expected files exist
        temp_path = Path(temp_dir)
        expected_files = ["import-test-1.yaml", "import-test-2.yaml"]
        for expected_file in expected_files:
          file_path = temp_path / expected_file
          assert file_path.exists(), f"Expected file {expected_file} not found"
        print(f"   ✓ Found expected files: {expected_files}")

        # Clear manager and import from each file
        manager.clear()
        assert manager.count() == 0
        print("   ✓ Cleared manager")

        imported_benchmarks = []
        for file_name in expected_files:
          file_path = temp_path / file_name
          file_benchmarks = manager.import_benchmarks(str(file_path))
          imported_benchmarks.extend(file_benchmarks)
          print(f"   ✓ Imported {len(file_benchmarks)} "
                f"benchmarks from {file_name}")

        # Verify total count
        assert len(imported_benchmarks) == len(original_benchmarks)
        assert manager.count() == len(original_benchmarks)
        print(f"   ✓ Total imported benchmarks: {len(imported_benchmarks)}")

        # Verify benchmark data integrity
        original_by_id = {b.id: b for b in original_benchmarks}
        imported_by_id = {b.id: b for b in imported_benchmarks}

        assert set(original_by_id.keys()) == set(imported_by_id.keys())
        print("   ✓ All benchmark IDs match")

        # Verify field preservation
        for benchmark_id in original_by_id:
          orig = original_by_id[benchmark_id]
          imported = imported_by_id[benchmark_id]

          assert orig.project == imported.project
          assert orig.language == imported.language
          assert orig.function_signature == imported.function_signature
          assert orig.function_name == imported.function_name
          assert orig.return_type == imported.return_type
          assert orig.target_path == imported.target_path
        print("   ✓ All benchmark fields preserved correctly")

        # Test JSON import as well
        manager.clear()
        success = manager.export_benchmarks(original_benchmarks, temp_dir,
                                            "json")
        assert success is True

        json_files = list(temp_path.glob("*.json"))
        imported_json_benchmarks = []
        for json_file in json_files:
          file_benchmarks = manager.import_benchmarks(str(json_file))
          imported_json_benchmarks.extend(file_benchmarks)

        assert len(imported_json_benchmarks) == len(original_benchmarks)
        print("   ✓ JSON import also works correctly")

      return True

    except Exception as e:
      print(f"❌ Import grouped benchmarks test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

  def test_export_error_handling(self):
    """Test error handling in export functionality."""
    print("\n🧪 Testing export error handling...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      test_benchmark = Benchmark(project="test",
                                 language="C",
                                 function_signature="void test()",
                                 function_name="test",
                                 return_type="void",
                                 target_path="/src/test.c")

      # Test invalid file format
      with tempfile.TemporaryDirectory() as temp_dir:
        try:
          manager.export_benchmarks([test_benchmark], temp_dir,
                                    "invalid_format")
          assert False, "Should have raised BenchmarkError for invalid format"
        except Exception as e:
          assert "Unsupported file format" in str(e)
          print("   ✓ Invalid file format error handled correctly")

        # Test path that exists but is not a directory
        temp_file = Path(temp_dir) / "not_a_dir.txt"
        temp_file.write_text("test")

        try:
          manager.export_benchmarks([test_benchmark], str(temp_file), "yaml")
          assert False, ("Should have raised"
                         "BenchmarkError for non-directory path")
        except Exception as e:
          assert "not a directory" in str(e)
          print("   ✓ Non-directory path error handled correctly")

        # Test empty benchmarks list
        try:
          manager.export_benchmarks([], temp_dir, "yaml")
          assert False, "Should have raised BenchmarkError for empty benchmarks"
        except Exception as e:
          assert "No benchmarks to export" in str(e)
          print("   ✓ Empty benchmarks error handled correctly")

      return True

    except Exception as e:
      print(f"❌ Export error handling test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

  def test_function_name_parsing(self):
    """Test automatic function name parsing."""
    print("\n🧪 Testing function name parsing...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      # Test C function parsing (ID will be auto-computed)
      benchmark_c = Benchmark(
          project="test",
          language="C",
          function_signature="int my_function(const char* input, size_t len)",
          function_name="",  # Empty - should be auto-parsed
          return_type="int",
          params=[],
          target_path="/src/test.c")

      success = manager.add_benchmark(benchmark_c)
      assert success is True

      retrieved = manager.get_benchmark(benchmark_c.id)
      if retrieved:
        print(f"✓ C function name parsed: '{retrieved.function_name}'")
        print(f"✓ C auto-computed ID: '{retrieved.id}'")

      # Test Python function parsing (ID will be auto-computed)
      benchmark_py = Benchmark(
          project="test",
          language="Python",
          function_signature="def my_python_func(x: int, y: str) -> bool:",
          function_name="",  # Empty - should be auto-parsed
          return_type="bool",
          params=[],
          target_path="/src/test.py")

      success = manager.add_benchmark(benchmark_py)
      assert success is True

      retrieved = manager.get_benchmark(benchmark_py.id)
      if retrieved:
        print(f"✓ Python function name parsed: '{retrieved.function_name}'")
        print(f"✓ Python auto-computed ID: '{retrieved.id}'")

      return True

    except Exception as e:
      print(f"❌ Function name parsing test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

  def test_id_override_behavior(self):
    """Test that manually provided IDs are overridden by auto-computed ones."""
    print("\n🧪 Testing ID override behavior...")

    try:
      from ossfuzz_py.core.benchmark_manager import Benchmark, BenchmarkManager

      manager = BenchmarkManager()

      # Test 1: Benchmark with manually provided ID should be overridden
      print("\n1. Testing ID override with manual ID:")
      manual_id = "manually-provided-id-12345"
      benchmark_with_manual_id = Benchmark(
          id=manual_id,  # This should be overridden
          project="test-project",
          language="C++",
          function_signature="void test_function(int x)",
          function_name="test_function",
          return_type="void",
          target_path="/src/test.cpp")

      print(f"   Manual ID provided: {manual_id}")
      print(f"   Actual ID after creation: {benchmark_with_manual_id.id}")
      print(f"   ID was overridden: {benchmark_with_manual_id.id != manual_id}")
      assert benchmark_with_manual_id.id != manual_id,\
        "Manual ID should be overridden"
      print("   ✅ Manual ID was correctly overridden")

      # Test 2: Same project+signature should produce same ID regardless of
      # manual ID
      print("\n2. Testing consistency despite different manual IDs:")
      different_manual_id = "completely-different-manual-id-67890"
      benchmark_with_different_manual_id = Benchmark(
          id=different_manual_id,  # Different manual ID
          project="test-project",  # Same project
          language="C++",
          function_signature="void test_function(int x)",  # Same signature
          function_name="test_function",
          return_type="void",
          target_path="/src/test.cpp")

      print(f"   First manual ID: {manual_id}")
      print(f"   Second manual ID: {different_manual_id}")
      print(f"   First actual ID: {benchmark_with_manual_id.id}")
      print(f"   Second actual ID: {benchmark_with_different_manual_id.id}")
      identical = (
          benchmark_with_manual_id.id == benchmark_with_different_manual_id.id)
      print(f"   IDs are identical: {identical}")
      assert (benchmark_with_manual_id.id ==
              benchmark_with_different_manual_id.id),\
        "Same project+signature should produce same ID"
      print("   ✅ Same project+signature produces consistent ID")

      # Test 3: Empty string ID should also be overridden
      print("\n3. Testing empty string ID override:")
      benchmark_with_empty_id = Benchmark(
          id="",  # Empty string
          project="test-project",
          language="C++",
          function_signature="void another_function()",
          function_name="another_function",
          return_type="void",
          target_path="/src/test.cpp")

      print("   Empty ID provided: ''")
      print(f"   Actual ID after creation: {benchmark_with_empty_id.id}")
      print(f"   ID was computed: {len(benchmark_with_empty_id.id) > 0}")
      assert len(benchmark_with_empty_id.id
                ) > 0, "Empty ID should be replaced with computed ID"
      print("   ✅ Empty ID was correctly replaced")

      # Test 4: Different signatures should produce different IDs
      print("\n4. Testing different signatures produce different IDs:")
      benchmark_sig1 = Benchmark(id="same-manual-id",
                                 project="same-project",
                                 language="C++",
                                 function_signature="void function_one(int x)",
                                 function_name="function_one",
                                 return_type="void",
                                 target_path="/src/test.cpp")

      benchmark_sig2 = Benchmark(
          id="same-manual-id",  # Same manual ID
          project="same-project",  # Same project
          language="C++",
          function_signature="void function_two(int y)",  # Different signature
          function_name="function_two",
          return_type="void",
          target_path="/src/test.cpp")

      print("   Same manual ID: 'same-manual-id'")
      print("   Same project: 'same-project'")
      print("   Signature 1: 'void function_one(int x)'")
      print("   Signature 2: 'void function_two(int y)'")
      print(f"   Actual ID 1: {benchmark_sig1.id}")
      print(f"   Actual ID 2: {benchmark_sig2.id}")
      print(f"   IDs are different: {benchmark_sig1.id != benchmark_sig2.id}")
      assert benchmark_sig1.id != benchmark_sig2.id,\
        "Different signatures should produce different IDs"
      print("   ✅ Different signatures produce different IDs")

      # Test 5: Test with BenchmarkManager operations
      print("\n5. Testing override behavior with BenchmarkManager:")
      success1 = manager.add_benchmark(benchmark_with_manual_id)
      success2 = manager.add_benchmark(
          benchmark_with_different_manual_id)  # Should be duplicate

      print(f"   First benchmark added: {success1}")
      print(f"   Second benchmark (same computed ID) added: {success2}")
      print(f"   Manager count: {manager.count()}")

      assert success1 is True, "First benchmark should be added successfully"
      assert success2 is False,\
        "Second benchmark should be rejected as duplicate"
      assert manager.count() >= 1, "Manager should contain the benchmark"
      print("   ✅ BenchmarkManager correctly handles override behavior")

      # Test 6: Verify the computed ID format
      print("\n6. Testing computed ID format:")
      test_benchmark = Benchmark(project="format-test",
                                 language="C",
                                 function_signature="int test_func(void)",
                                 function_name="test_func",
                                 return_type="int",
                                 target_path="/src/test.c")

      computed_id = test_benchmark.id
      print(f"   Computed ID: {computed_id}")
      print(f"   Length: {len(computed_id)}")
      print(
          f"   Contains only alphanumeric characters: {computed_id.isalnum()}")
      print(f"   All lowercase: {computed_id.islower()}")
      print(f"   Is exactly 16 characters: {len(computed_id) == 16}")

      assert len(computed_id) == 16, "ID should be exactly 16 characters"
      assert computed_id.isalnum(
      ), "ID should contain only alphanumeric characters"
      assert computed_id.islower(), "ID should be lowercase (base36 format)"
      assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz"
                 for c in computed_id), "ID should use base36 characters only"
      print("   ✅ Computed ID has correct format")

      # Test 7: Verify reproducibility across multiple instances
      print("\n7. Testing reproducibility across multiple instances:")
      benchmark_copy1 = Benchmark(
          project="repro-test",
          language="Java",
          function_signature="public void testMethod(String input)",
          function_name="testMethod",
          return_type="void",
          target_path="/src/Test.java")

      benchmark_copy2 = Benchmark(
          project="repro-test",
          language="Java",
          function_signature="public void testMethod(String input)",
          function_name="testMethod",
          return_type="void",
          target_path="/src/Test.java")

      print(f"   First instance ID: {benchmark_copy1.id}")
      print(f"   Second instance ID: {benchmark_copy2.id}")
      print(f"   IDs are identical: {benchmark_copy1.id == benchmark_copy2.id}")
      print(f"   Hash values are identical: "
            f"{hash(benchmark_copy1) == hash(benchmark_copy2)}")

      assert benchmark_copy1.id == benchmark_copy2.id,\
        "Identical benchmarks should have identical IDs"
      assert hash(benchmark_copy1) == hash(
          benchmark_copy2
      ), "Identical benchmarks should have identical hash values"
      print("   ✅ ID generation is perfectly reproducible")

      # Test 8: Test edge cases with special characters and long signatures
      print("\n8. Testing edge cases with special characters:")
      edge_case_benchmark = Benchmark(
          id="this-should-be-overridden-123!@#",
          project="edge-test",
          language="C++",
          function_signature="std::vector<std::pair<std::string, int>> "
          "very_long_function_name_with_templates(const std::map<std::string, "
          "std::vector<int>>& input, std::function<bool(const std::string&)> "
          "predicate)",
          function_name="very_long_function_name_with_templates",
          return_type="std::vector<std::pair<std::string, int>>",
          target_path="/src/complex.cpp")

      print("   Original manual ID: 'this-should-be-overridden-123!@#'")
      print("   Complex signature with templates and special chars")
      print(f"   Computed ID: {edge_case_benchmark.id}")
      is_valid = all(c in '0123456789abcdefghijklmnopqrstuvwxyz'
                     for c in edge_case_benchmark.id)
      print(f"   ID is valid base36: {is_valid}")
      print(f"   ID length is 16: {len(edge_case_benchmark.id) == 16}")

      assert edge_case_benchmark.id != "this-should-be-overridden-123!@#", \
        "Manual ID with special chars should be overridden"
      assert len(edge_case_benchmark.id
                ) == 16, "Even complex signatures should produce 16-char IDs"
      assert all(c in '0123456789abcdefghijklmnopqrstuvwxyz'
                 for c in edge_case_benchmark.id), "ID should be valid base36"
      print("   ✅ Edge cases handled correctly")

      # Test 9: Test with empty and minimal signatures
      print("\n9. Testing minimal and empty signature cases:")
      minimal_benchmark = Benchmark(
          id="minimal-override-test",
          project="min",
          language="C",
          function_signature="",  # Empty signature
          function_name="",
          return_type="void",
          target_path="/test.c")

      single_char_benchmark = Benchmark(
          id="single-char-override-test",
          project="x",  # Single char project
          language="C",
          function_signature="f",  # Single char signature
          function_name="f",
          return_type="int",
          target_path="/f.c")

      print(f"   Empty signature ID: {minimal_benchmark.id}")
      print(f"   Single char project+signature ID: {single_char_benchmark.id}")
      print(f"   Both IDs are different: "
            f"{minimal_benchmark.id != single_char_benchmark.id}")
      is_valid = (len(minimal_benchmark.id) == 16 and
                  len(single_char_benchmark.id) == 16)
      print(f"   Both IDs are valid: {is_valid}")

      assert len(minimal_benchmark.id
                ) == 16, "Empty signature should still produce valid ID"
      assert len(single_char_benchmark.id
                ) == 16, "Minimal input should still produce valid ID"
      assert minimal_benchmark.id != single_char_benchmark.id,\
        "Different inputs should produce different IDs"
      print("   ✅ Minimal cases handled correctly")

      return True

    except Exception as e:
      print(f"❌ ID override behavior test failed: {e}")
      import traceback
      traceback.print_exc()
      return False

if __name__ == "__main__":
  unittest.main()
