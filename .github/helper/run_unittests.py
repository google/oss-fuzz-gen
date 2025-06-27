#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""
Unittest runner for Python modules in the same style as OSS-Fuzz.
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from typing import List

# --------------------------------------------------------------------------- #
# Helper utilities                                                            #
# --------------------------------------------------------------------------- #


def get_repo_root(start_path: Path | None = None) -> Path:
  """Return the repository root directory (folder that owns ``.git``)."""
  path = Path(start_path or __file__).resolve()
  for parent in [path] + list(path.parents):
    if (parent / ".git").exists():
      return parent
  return Path.cwd()


def bool_to_return_code(success: bool) -> int:  # noqa: D401
  """Map *success* to a shell‑friendly exit code (0 OK, 1 fail)."""
  return 0 if success else 1


# --------------------------------------------------------------------------- #
# Test discovery helpers                                                      #
# --------------------------------------------------------------------------- #

TEST_FILE_PATTERN = "test_*.py"


def _build_loader() -> unittest.TestLoader:
  """Create a loader that keeps test methods in definition order."""
  loader = unittest.TestLoader()
  loader.sortTestMethodsUsing = None  # type: ignore[assignment]
  return loader


def _flatten_suite(suite: unittest.TestSuite) -> List[unittest.TestCase]:
  """Recursively collect concrete ``TestCase`` instances from *suite*."""
  cases: List[unittest.TestCase] = []
  for item in suite:  # type: ignore[not-an-iterable]
    if isinstance(item, unittest.TestSuite):
      cases.extend(_flatten_suite(item))
    else:
      cases.append(item)
  return cases


def discover_test_cases(start_dir: Path) -> unittest.TestSuite:
  """Return a *flat* :class:`unittest.TestSuite` of TestCase objects."""
  loader = _build_loader()
  discovered = loader.discover(str(start_dir), pattern=TEST_FILE_PATTERN)
  flat_cases = _flatten_suite(discovered)
  return unittest.TestSuite(flat_cases)


# --------------------------------------------------------------------------- #
# Execution logic                                                             #
# --------------------------------------------------------------------------- #


def run_test_suite(suite: unittest.TestSuite) -> bool:
  """Run *suite* and return ``True`` on success, ``False`` otherwise."""
  runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
  result = runner.run(suite)
  return result.wasSuccessful()


def discover_and_run_tests(test_directory: Path) -> bool:
  """Discover TestCases under *test_directory* and execute them."""
  if not test_directory.exists():
    print(f"Test directory does not exist: {test_directory}")
    return False
  if not test_directory.is_dir():
    print(f"Test path is not a directory: {test_directory}")
    return False

  print(f"Discovering tests in: {test_directory}")

  # Ensure the project root is importable for local modules
  project_root = get_repo_root()
  if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

  suite = discover_test_cases(test_directory)
  test_count = suite.countTestCases()

  if test_count == 0:
    print(f"No tests found in {test_directory}")
    return True  # Zero tests is considered success

  print(f"Found {test_count} test case(s)")
  return run_test_suite(suite)


def validate_test_directory(test_directory: Path) -> bool:
  """Quick sanity‑check that *test_directory* is a valid test root."""
  return test_directory.is_dir() and any(test_directory.glob(TEST_FILE_PATTERN))


# --------------------------------------------------------------------------- #
# CLI entry‑point                                                             #
# --------------------------------------------------------------------------- #


def main() -> int:  # noqa: D401 – imperative is fine
  parser = argparse.ArgumentParser(description="Run Python unittests.")
  parser.add_argument(
      "test_directories",
      nargs="*",
      default=["ossfuzz_py/unittests"],
      help="Directories (relative to repo root) containing tests.",
  )
  parser.add_argument("--verbose",
                      "-v",
                      action="store_true",
                      help="Verbose output")

  args = parser.parse_args()
  if args.verbose:
    print(f"CLI test directories: {args.test_directories}")

  repo_root = get_repo_root()
  overall_success = True

  for raw_dir in args.test_directories:
    test_dir = Path(raw_dir)
    if not test_dir.is_absolute():
      test_dir = repo_root / test_dir
    test_dir = test_dir.resolve()

    print("\n" + "=" * 60)
    print(f"Running tests in: {test_dir}")
    print("=" * 60)

    if not validate_test_directory(test_dir):
      print(f"Skipping invalid test directory: {test_dir}")
      continue

    if not discover_and_run_tests(test_dir):
      overall_success = False

  return bool_to_return_code(overall_success)


if __name__ == "__main__":
  sys.exit(main())
