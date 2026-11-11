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
"""Tests for agent path normalization."""

import os
import pathlib
import sys
import tempfile
import unittest

# The repository root also contains a legacy ``utils.py`` module. Put the
# bundled agent directory first so this test imports the agent's utils package.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
if 'utils' in sys.modules and not hasattr(sys.modules['utils'], '__path__'):
  del sys.modules['utils']

# 🔑 升级：将导入源重构为解耦后的物理 path_utils，杜绝由于外部 ADK/LLM 依赖导致的加载缓慢
from utils.path_utils import normalize_patch_path


class TestNormalizePatchPath(unittest.TestCase):
  """Test cross-host path normalization without host-specific paths."""

  def setUp(self):
    # Create a temporary directory to isolate the simulated project root.
    self.temp_dir = tempfile.TemporaryDirectory()
    self.base_dir = self.temp_dir.name

    # 2. Dynamically build the standard project structure
    self.oss_fuzz_dir = os.path.join(self.base_dir,
                                     "oss-fuzz/projects/cert-manager")
    self.src_dir = os.path.join(self.base_dir, "process/project/cert-manager")
    os.makedirs(self.oss_fuzz_dir, exist_ok=True)
    os.makedirs(self.src_dir, exist_ok=True)

  def tearDown(self):
    self.temp_dir.cleanup()

  def test_absolute_to_relative(self):
    """Absolute path → relative path (based on dynamic base_dir)"""
    abs_path = os.path.join(self.oss_fuzz_dir, "build.sh")
    result = normalize_patch_path(abs_path, base_dir=self.base_dir)
    self.assertEqual(result, "oss-fuzz/projects/cert-manager/build.sh")

  def test_relative_path_passthrough(self):
    """Already a relative path → keep as is (no redundant prefix added)"""
    rel_path = "process/project/cert-manager/go.mod"
    result = normalize_patch_path(rel_path, base_dir=self.base_dir)
    self.assertEqual(result, rel_path)

  def test_cross_platform_slash_normalization(self):
    """Windows-style backslashes → uniformly converted to forward slashes"""
    win_path = "oss-fuzz\\projects\\cert-manager\\build.sh"
    result = normalize_patch_path(win_path, base_dir=self.base_dir)
    self.assertEqual(result, "oss-fuzz/projects/cert-manager/build.sh")
    self.assertNotIn("\\", result)

  def test_depth_traversal_cleanup(self):
    """Clean up redundant ../ and ./ symbols"""
    messy_path = os.path.join(self.base_dir, "process/project/cert-manager",
                              "..", "cert-manager", "./go.mod")
    result = normalize_patch_path(messy_path, base_dir=self.base_dir)
    self.assertEqual(result, "process/project/cert-manager/go.mod")

  def test_empty_path_handling(self):
    """Empty string or blank path → return safely"""
    self.assertEqual(normalize_patch_path("", base_dir=self.base_dir), "")
    self.assertEqual(normalize_patch_path("   ", base_dir=self.base_dir), "   ")


if __name__ == "__main__":
  unittest.main()
