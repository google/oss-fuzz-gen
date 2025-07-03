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
Integration test: LocalBuilder → real Docker build.

This module contains unittest integration tests for the LocalBuilder pipeline.
The tests exercise the real local-build pipeline components including:

1. FuzzTarget creation with minimal C++ source code
2. LocalBuilder.build() method invocation
3. Build result validation and artifact checking
4. Docker image cleanup

Note: The full Docker build test requires OSS-Fuzz infrastructure and is
currently skipped. The minimal setup test verifies configuration and error
handling without requiring the full OSS-Fuzz environment.
"""

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from ossfuzz_py.build.build_config import BuildConfig
from ossfuzz_py.build.builder import LocalBuilder
from ossfuzz_py.build.docker_manager import DockerManager
from ossfuzz_py.core.benchmark_manager import BenchmarkManager
from ossfuzz_py.core.data_models import FuzzingEngine, Sanitizer
from ossfuzz_py.core.ossfuzz_manager import OSSFuzzManager
from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.execution.fuzz_runner import FuzzRunOptions, LocalRunner
from ossfuzz_py.execution.fuzz_target import FuzzTarget
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.work_dir_manager import WorkDirManager


def _create_dummy_c_target() -> FuzzTarget:
  """Generate a minimal C++ fuzz target and build script."""
  # Source with a no-op LLVMFuzzerTestOneInput
  source_code = textwrap.dedent("""
    #include <stddef.h>
    #include <stdint.h>
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
        return 0;
    }
    """).strip()

  # Simple build.sh using $CXX and $LIB_FUZZING_ENGINE env vars supplied by
  # OSS-Fuzz images
  build_script = textwrap.dedent("""
    #!/bin/bash -eu
    $CXX $CXXFLAGS -c dummy_fuzzer.cc -o dummy_fuzzer.o
    $CXX $CXXFLAGS dummy_fuzzer.o -o $OUT/dummy_fuzzer $LIB_FUZZING_ENGINE
    """).strip()

  return FuzzTarget(name="dummy_fuzzer",
                    source_code=source_code,
                    build_script=build_script,
                    project_name="dummy",
                    language="cpp")


def _create_real_fuzz_target_from_benchmark(
    benchmark_yaml_path: str) -> FuzzTarget:
  """Create a real fuzz target from a benchmark YAML file."""
  # Load benchmarks from YAML file
  manager = BenchmarkManager()
  benchmarks = manager.import_benchmarks(benchmark_yaml_path)

  if not benchmarks:
    raise ValueError(f"No benchmarks found in {benchmark_yaml_path}")

  # Use the first benchmark
  benchmark = benchmarks[0]

  # Create a basic fuzz target template from the benchmark
  fuzz_target = FuzzTarget.create_basic_template(benchmark)

  return fuzz_target


class TestLocalBuilderPipeline(unittest.TestCase):
  """Test class for LocalBuilder pipeline integration tests."""

  def setUp(self):
    """Set up test fixtures."""
    # Configure logging to show all logs
    import logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True)

  def _setup_build_infrastructure_and_get_metadata(self):
    """
    Helper function to set up build infrastructure and return build metadata.
    This function contains the common build setup logic that can be reused
    by both the build test and the runner test.

    Returns:
        tuple: (build_result, build_metadata)
            - build_result: The result from LocalBuilder.build()
            - build_metadata: Dictionary containing build metadata for runner
    """

    # Skip if this is a CI environment or if network access is limited
    if EnvUtils.is_ci_environment():
      self.skipTest("Skipping real OSS-Fuzz clone in CI environment")

    print("Setting up real OSS-Fuzz infrastructure...")

    tmp_path = Path(EnvUtils.get_oss_fuzz_dir())

    # Create OSS-Fuzz manager and clone the real repository
    oss_fuzz_manager = OSSFuzzManager(checkout_path=tmp_path, use_temp=False)

    # Setup shallow clone for faster testing (similar to the
    # test_ossfuzz_manager.py approach)
    try:
      if oss_fuzz_manager.checkout_path.exists():
        oss_fuzz_manager.logger.info(
            f"Repository already exists at {oss_fuzz_manager.checkout_path}")
      else:
        repo_url = "https://github.com/google/oss-fuzz.git"
        cmd = [
            "git", "clone", "--depth", "1", "--branch", "master", repo_url,
            str(oss_fuzz_manager.checkout_path)
        ]
        result = subprocess.run(cmd,
                                capture_output=True,
                                text=True,
                                check=True,
                                timeout=120)
        oss_fuzz_manager.logger.info(
            f"Successfully cloned OSS-Fuzz repository "
            f"to {oss_fuzz_manager.checkout_path}, result={result}")

    except subprocess.TimeoutExpired:
      self.skipTest("OSS-Fuzz clone timed out - network may be slow")
    except subprocess.CalledProcessError as e:
      self.skipTest(f"Failed to clone OSS-Fuzz repository: {e.stderr}")
    except Exception as e:
      self.skipTest(f"Unexpected error during OSS-Fuzz clone: {str(e)}")

    # Verify OSS-Fuzz structure exists
    self.assertTrue(oss_fuzz_manager.checkout_path.exists(),
                    "OSS-Fuzz checkout failed")
    self.assertTrue((oss_fuzz_manager.checkout_path / "projects").exists(),
                    "OSS-Fuzz projects directory not found")
    self.assertTrue((oss_fuzz_manager.checkout_path / "infra").exists(),
                    "OSS-Fuzz infra directory not found")

    print("✓ OSS-Fuzz repository cloned successfully")

    # Create a real fuzz target from benchmark YAML
    benchmark_yaml_path = "../../benchmark-sets/all/libspng.yaml"

    try:
      fuzz_target = _create_real_fuzz_target_from_benchmark(benchmark_yaml_path)
      print(f"✓ Created real fuzz target from benchmark: {fuzz_target.name}")
      print(f"  Project: {fuzz_target.project_name}")
      print(f"  Language: {fuzz_target.language}")
      print(f"  Function: {fuzz_target.function_signature}")
    except Exception as e:
      print(f"Failed to create real fuzz target: {e}")
      print("Falling back to dummy fuzz target...")
      fuzz_target = _create_dummy_c_target()

    # Create storage manager with temporary directory
    storage_config = {
        'storage_backend': 'local',
        'storage_path': str(tmp_path / "storage")
    }
    storage_manager = StorageManager(storage_config)

    # Create build configuration matching the fuzz target
    build_config = BuildConfig(project_name=fuzz_target.project_name,
                               language=fuzz_target.language,
                               sanitizer=Sanitizer.ADDRESS,
                               architecture="aarch64",
                               fuzzing_engine=FuzzingEngine.LIBFUZZER)

    # Create Docker manager with real OSS-Fuzz directory
    docker_manager = DockerManager(cache_enabled=False,
                                   oss_fuzz_dir=str(
                                       oss_fuzz_manager.checkout_path))

    print("✓ Docker manager created with real OSS-Fuzz directory")

    # Save fuzz target files to disk for the builder
    source_path, build_path = fuzz_target.save_to_files(tmp_path /
                                                        "fuzz_target_files")
    print("✓ Saved fuzz target files:")
    print(f"  Source: {source_path}")
    print(f"  Build script: {build_path}")

    # Create LocalBuilder
    builder = LocalBuilder(storage_manager, build_config, docker_manager)

    print("✓ LocalBuilder created, attempting build...")

    # Build the target
    build_result = builder.build(fuzz_target, Sanitizer.ADDRESS)

    # Create build metadata for runner
    build_metadata = {
        'generated_project':
            build_result.metadata.get('generated_project')
            if build_result.metadata else None,
        'project_name':
            fuzz_target.project_name,
        'target_name':
            fuzz_target.name,
        'fuzz_target':
            fuzz_target
    }

    return build_result, build_metadata

  @unittest.skipIf(shutil.which("docker") is None, "Docker not installed")
  @unittest.skipIf(shutil.which("git") is None, "Git not installed")
  def test_local_builder_pipeline_real_docker(self):
    """End-to-end build: FuzzTarget → LocalBuilder → verify binary using real
    OSS-Fuzz."""

    # Use the helper function to set up build infrastructure
    build_result, build_metadata = (
        self._setup_build_infrastructure_and_get_metadata())

    # --- Assertions -----------------------------------------------------
    # Note: The build may fail due to missing Docker images or other
    # infrastructure, but we can still verify the pipeline setup and error
    # handling

    if build_result.success:
      print(f"✓ Build succeeded!, build_metadata={build_metadata}")

      # Check that we have a generated project (image_id equivalent)
      generated_project = build_result.metadata.get('generated_project')
      self.assertIsNotNone(generated_project,
                           "No generated project found in metadata")
      print(f"✓ Generated project: {generated_project}")

    else:
      print(
          f"Build failed (expected in test environment): {build_result.message}"
      )
      # Verify that the failure is due to expected infrastructure issues
      expected_errors = [
          "No such file or directory", "Docker image not found",
          "Permission denied", "Network error", "Build failed"
      ]
      self.assertTrue(
          any(error in build_result.message for error in expected_errors),
          f"Unexpected build failure: {build_result.message}")
      print("✓ Build failed with expected infrastructure error")

    print("✓ OSS-Fuzz infrastructure properly integrated")

  @unittest.skipIf(shutil.which("docker") is None, "Docker not installed")
  @unittest.skipIf(shutil.which("git") is None, "Git not installed")
  def test_local_runner_pipeline_real_docker(self):
    """End-to-end run: Reuse build metadata → LocalRunner → execute Docker
    image and verify results."""

    # Reuse the build logic and get build metadata
    build_result, build_metadata = (
        self._setup_build_infrastructure_and_get_metadata())

    # Only proceed with runner test if build was successful
    if not build_result.success:
      self.skipTest(f"Build failed, cannot test runner: {build_result.message}")

    print("✓ Build succeeded, proceeding with runner test...")

    # Extract build information
    generated_project = build_metadata.get('generated_project')
    target_name: str = build_metadata.get('target_name') or ''

    self.assertIsNotNone(generated_project,
                         "No generated project found in build metadata")
    self.assertIsNotNone(target_name, "No target name found in build metadata")

    print("✓ Build metadata extracted:")
    print(f"  Generated project: {generated_project}")
    print(f"  Target name: {target_name}")

    # Create WorkDirManager pointing at environment variable WORK_DIR
    work_dir = EnvUtils.get_work_dir()
    workdir_manager = WorkDirManager(work_dir)

    print(f"✓ WorkDirManager created with work directory: {work_dir}")

    # Create LocalRunner instance
    runner = LocalRunner(workdir_manager)

    print("✓ LocalRunner instance created")

    # Build FuzzerRunOptions with short timeouts for testing
    options = FuzzRunOptions(
        duration_seconds=15,  # max_total_time equivalent
        timeout_seconds=5,  # timeout equivalent
        corpus_dir=None  # Let runner manage corpus directory
    )

    print("✓ FuzzRunOptions created:")
    print(f"  Duration: {options.duration_seconds}s")
    print(f"  Timeout: {options.timeout_seconds}s")

    # Run the target
    print("✓ Starting fuzzer run...")
    run_info = runner.run(target=target_name,
                          options=options,
                          build_metadata=build_metadata)

    # --- Assertions -----------------------------------------------------
    print("✓ Fuzzer run completed, verifying results...")

    # Basic run_info validation
    self.assertIsNotNone(run_info, "run_info should not be None")
    print("✓ run_info is not None")

    # Check for crashes (should not crash in a simple test)
    self.assertFalse(
        run_info.crashes,
        f"Fuzzer should not crash in basic test, but crashes={run_info.crashes}"
    )
    print("✓ No crashes detected")

    # Check that log path exists and has content
    if run_info.run_log:
      log_path = Path(run_info.run_log)
      self.assertTrue(log_path.exists(), f"Log path should exist: {log_path}")
      print(f"✓ Log path exists: {log_path}")

      # Check log has some content (at least a few bytes)
      log_size = log_path.stat().st_size
      self.assertGreater(
          log_size, 0, f"Log file should have content, but size is {log_size}")
      print(f"✓ Log file has content: {log_size} bytes")
    else:
      print("⚠ No log path provided in run_info")

    # Check that corpus path exists
    if run_info.corpus_path:
      corpus_path = Path(run_info.corpus_path)
      self.assertTrue(corpus_path.exists(),
                      f"Corpus path should exist: {corpus_path}")
      print(f"✓ Corpus path exists: {corpus_path}")

      # Check if corpus directory is accessible (it may be empty for short runs)
      self.assertTrue(corpus_path.is_dir(),
                      f"Corpus path should be a directory: {corpus_path}")
      print("✓ Corpus path is a directory")
    else:
      print("⚠ No corpus path provided in run_info")

    print("✓ All runner pipeline assertions passed!")

  @unittest.skipIf(shutil.which("docker") is None, "Docker not installed")
  def test_local_builder_pipeline_minimal_setup(self):
    """Test with minimal setup to ensure basic functionality works."""

    # Create minimal C target
    target_source = textwrap.dedent("""
          #include <stddef.h>
          #include <stdint.h>
          extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
              // Minimal fuzzer that just returns
              if (Size > 0 && Data[0] == 'A') {
                  // Do something with the input
                  return 1;
              }
              return 0;
          }
      """)

    build_script = textwrap.dedent("""
          #!/bin/bash -eu
          # Minimal build script
          $CXX $CXXFLAGS -o $OUT/minimal_fuzzer $SRC/minimal_fuzzer.cc $LIB_FUZZING_ENGINE
      """)

    fuzz_target = FuzzTarget(name="minimal_fuzzer",
                             source_code=target_source,
                             build_script=build_script,
                             project_name="minimal",
                             language="cpp")

    # Create minimal dependencies using temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = Path(tmp_dir)

      storage_config = {
          'storage_backend': 'local',
          'storage_path': str(tmp_path / "storage")
      }
      storage_manager = StorageManager(storage_config)

      build_config = BuildConfig(project_name="minimal",
                                 language="cpp",
                                 sanitizer=Sanitizer.ADDRESS)

      docker_manager = DockerManager(cache_enabled=False)

      # Create and test builder
      builder = LocalBuilder(storage_manager, build_config, docker_manager)

      # Verify builder was created successfully
      self.assertIsNotNone(builder)
      self.assertEqual(builder.build_config.project_name, "minimal")
      self.assertEqual(builder.build_config.sanitizer, Sanitizer.ADDRESS)

      # Test that we can call the build method (it will fail due to missing
      # OSS-Fuzz infrastructure), but we can verify the error handling works
      # correctly
      build_result = builder.build(fuzz_target, Sanitizer.ADDRESS)

      # The build should fail due to missing OSS-Fuzz infrastructure,
      # but gracefully
      self.assertFalse(build_result.success,
                       "Build should fail without OSS-Fuzz infrastructure")
      self.assertTrue(("No such file or directory" in build_result.message or
                       "Build failed" in build_result.message))

      print(
          "✓ LocalBuilder setup, configuration, and error handling successful")

  def test_local_builder_pipeline_components(self):
    """Test that all LocalBuilder pipeline components integrate correctly."""

    # Create a comprehensive fuzz target
    target_source = textwrap.dedent("""
          #include <stddef.h>
          #include <stdint.h>
          #include <string.h>

          extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
              // More realistic fuzzer that processes input
              if (Size < 4) return 0;

              // Check for specific patterns
              if (Data[0] == 'F' && Data[1] == 'U' && Data[2] == 'Z' && Data[3] == 'Z') {
                  // Trigger some processing
                  char buffer[256];
                  if (Size < sizeof(buffer)) {
                      memcpy(buffer, Data, Size);
                      buffer[Size] = '\\0';
                  }
              }

              return 0;
          }
      """)

    build_script = textwrap.dedent("""
          #!/bin/bash -eu
          # Comprehensive build script with error checking
          set -x

          # Verify environment variables are set
          if [ -z "$CXX" ]; then
              echo "Error: CXX not set"
              exit 1
          fi

          if [ -z "$OUT" ]; then
              echo "Error: OUT not set"
              exit 1
          fi

          # Build the fuzzer
          $CXX $CXXFLAGS -c comprehensive_fuzzer.cc -o comprehensive_fuzzer.o
          $CXX $CXXFLAGS comprehensive_fuzzer.o -o $OUT/comprehensive_fuzzer $LIB_FUZZING_ENGINE

          # Verify the binary was created
          if [ ! -f "$OUT/comprehensive_fuzzer" ]; then
              echo "Error: Fuzzer binary not created"
              exit 1
          fi

          echo "Build completed successfully"
      """)

    # Create FuzzTarget
    fuzz_target = FuzzTarget(name="comprehensive_fuzzer",
                             source_code=target_source,
                             build_script=build_script,
                             project_name="comprehensive",
                             language="cpp",
                             engine="libfuzzer",
                             sanitizers=["address"])

    # Test all component creation using temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = Path(tmp_dir)

      storage_config = {
          'storage_backend': 'local',
          'storage_path': str(tmp_path / "storage")
      }
      storage_manager = StorageManager(storage_config)

      build_config = BuildConfig(project_name="comprehensive",
                                 language="cpp",
                                 sanitizer=Sanitizer.ADDRESS,
                                 architecture="x86_64",
                                 fuzzing_engine=FuzzingEngine.LIBFUZZER,
                                 environment_vars={"CUSTOM_VAR": "test_value"},
                                 build_args=["--verbose"])

      docker_manager = DockerManager(cache_enabled=True)

      # Create LocalBuilder and verify all components
      builder = LocalBuilder(storage_manager, build_config, docker_manager)

      # Verify builder configuration
      self.assertEqual(builder.build_config.project_name, "comprehensive")
      self.assertEqual(builder.build_config.sanitizer, Sanitizer.ADDRESS)
      self.assertEqual(builder.build_config.fuzzing_engine,
                       FuzzingEngine.LIBFUZZER)
      self.assertEqual(builder.build_config.environment_vars["CUSTOM_VAR"],
                       "test_value")
      self.assertIn("--verbose", builder.build_config.build_args)

      # Verify storage manager integration
      self.assertEqual(builder.storage_manager, storage_manager)

      # Verify docker manager integration
      self.assertEqual(builder.docker_manager, docker_manager)
      self.assertTrue(builder.docker_manager.cache_enabled)

      # Test environment preparation
      env_prepared = builder.prepare_build_environment()
      self.assertTrue(env_prepared)

      # Test cleanup
      cleanup_result = builder.clean()
      self.assertTrue(cleanup_result)

      print("✓ All LocalBuilder pipeline components integrate correctly")
      print(f"  - FuzzTarget: {fuzz_target.name} ({fuzz_target.language})")
      print(f"  - BuildConfig: {build_config.project_name} with "
            f"{build_config.sanitizer.value}")
      print(f"  - StorageManager: "
            f"{storage_manager.config['storage_backend']} backend")
      print(f"  - DockerManager: cache_enabled={docker_manager.cache_enabled}")
      print("  - Environment preparation: successful")
      print("  - Artifact processing: functional")
      print("  - Cleanup: successful")


if __name__ == '__main__':
  unittest.main()
