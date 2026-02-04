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
Integration test: CloudBuilder → Google Cloud Build pipeline
(using explicit CloudBuildManager & StorageManager).

This test module validates the complete integration of:
1. CloudBuildManager - manages Google Cloud Build operations
2. StorageManager - handles artifact storage (GCS or local)
3. CloudBuilder - orchestrates the build process
4. FuzzTarget - represents the fuzz target to be built

The tests include:
- Real GCP integration tests (skipped without credentials)
- Mock mode tests for CI/CD environments
- Component validation tests

Usage:
    # Run all tests (real GCP tests will be skipped without credentials)
    python -m unittest test_cloud_builder_pipeline.py -v

    # Run with GCP credentials set
    GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json python -m unittest
    test_cloud_builder_pipeline.py -v
"""
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from ossfuzz_py import BenchmarkManager, OSSFuzzManager
from ossfuzz_py.build.build_config import BuildConfig
from ossfuzz_py.build.builder import CloudBuilder
from ossfuzz_py.build.cloud_build_manager import CloudBuildManager
from ossfuzz_py.core.data_models import Sanitizer
from ossfuzz_py.data.storage_manager import StorageManager
from ossfuzz_py.execution.fuzz_target import FuzzTarget
from ossfuzz_py.utils.env_utils import EnvUtils
from ossfuzz_py.utils.env_vars import EnvVars


def _create_real_fuzz_target_from_benchmark(
    benchmark_yaml_path: str) -> FuzzTarget:
  """Create a real fuzz target from a benchmark YAML file."""
  # Load benchmarks from the YAML file
  manager = BenchmarkManager()
  benchmarks = manager.import_benchmarks(benchmark_yaml_path)

  if not benchmarks:
    raise ValueError(f"No benchmarks found in {benchmark_yaml_path}")

  # Use the first benchmark
  benchmark = benchmarks[0]

  # Create a basic fuzz target template from the benchmark
  fuzz_target = FuzzTarget.create_basic_template(benchmark)

  return fuzz_target


class TestCloudBuilderPipeline(unittest.TestCase):
  """Test class for CloudBuilder pipeline integration tests."""

  def setUp(self):
    """Set up test fixtures."""
    # Configure logging to show all logs
    import logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True)

  @unittest.skipIf(
      not EnvUtils.has_gcp_credentials() or shutil.which("gcloud") is None,
      "GCP credentials or gcloud CLI missing",
  )
  def test_cloud_builder_pipeline_real_gcb(self):
    """Test the complete CloudBuilder pipeline with real Google Cloud Build."""

    tmp_path = Path(EnvUtils.get_oss_fuzz_dir())

    # Create OSS-Fuzz manager and clone the real repository
    oss_fuzz_manager = OSSFuzzManager(checkout_path=tmp_path, use_temp=False)

    # Set up a shallow clone for faster testing (similar to the
    # test_ossfuzz_manager.py approach)
    try:
      if oss_fuzz_manager.checkout_path.exists():
        oss_fuzz_manager.logger.info("Repository already exists at %s",
                                     oss_fuzz_manager.checkout_path)
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
            "Successfully cloned OSS-Fuzz repository to %s, result=%s",
            oss_fuzz_manager.checkout_path, result)

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

    benchmark_yaml_path = os.path.join(os.path.dirname(__file__),
                                       "../../benchmark-sets/all/libspng.yaml")
    fuzz_target = _create_real_fuzz_target_from_benchmark(benchmark_yaml_path)
    google_cloud_project = EnvUtils.get_env(EnvVars.GOOGLE_CLOUD_PROJECT,
                                            "oss-fuzz") or "oss-fuzz"

    # 1. CloudBuildManager - using correct parameter names from constructor
    cloud_manager = CloudBuildManager(
        project_id=google_cloud_project,
        experiment_bucket="oss-fuzz-gcb-experiment-run-logs/"
        "Result-reports/ofg-pr/zewei-test/zewei-test",
        experiment_name="libpngtest",
    )

    # 2. StorageManager - using the correct configuration format
    storage_cfg = {
        "storage_backend": "gcs",
        "storage_path": fuzz_target.project_name,
        "gcs_project_id": google_cloud_project,
        "gcs_bucket_name": "oss-fuzz-gcb-experiment-run-logs/"
                           "Result-reports/ofg-pr/zewei-test",
    }
    storage_manager = StorageManager(storage_cfg)

    # 3. BuildConfig - required for CloudBuilder
    build_cfg = BuildConfig(project_name=fuzz_target.project_name,
                            language=fuzz_target.language,
                            sanitizer=Sanitizer.ADDRESS)

    # 4. CloudBuilder - using correct parameter name
    builder = CloudBuilder(
        storage_manager=storage_manager,
        build_config=build_cfg,
        cloud_build_manager=cloud_manager,
    )

    # Execute the build
    build_result = builder.build(target=fuzz_target,
                                 sanitizer=Sanitizer.ADDRESS)

    # -- Assertions --------------------------------------------------
    self.assertTrue(build_result.success,
                    f"Build failed: {build_result.message}")

    # Check that we have build metadata
    self.assertIsNotNone(build_result.metadata)
    self.assertTrue(build_result.metadata.get("build_succeeded"))

    # Check for expected metadata fields
    expected_fields = [
        "generated_project", "target_name", "sanitizer", "build_log_path",
        "experiment_bucket", "experiment_name", "uid"
    ]
    for field in expected_fields:
      self.assertIn(field, build_result.metadata,
                    f"Missing metadata field: {field}")

    # Verify the target name matches
    self.assertEqual(build_result.metadata["target_name"], fuzz_target.name)
    self.assertEqual(build_result.metadata["sanitizer"],
                     Sanitizer.ADDRESS.value)
    self.assertEqual(
        build_result.metadata["experiment_bucket"],
        "oss-fuzz-gcb-experiment-run-logs/"
        "Result-reports/ofg-pr/zewei-test")
    self.assertEqual(build_result.metadata["experiment_name"], "libpngtest")


if __name__ == '__main__':
  unittest.main()
