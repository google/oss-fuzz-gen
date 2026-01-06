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
Unittest runner for Python modules using the built-in unittest framework.
"""

from __future__ import annotations

import argparse
import importlib.util
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
# Helper utilities                                                            #
# --------------------------------------------------------------------------- #

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


def run_specific_test_files(test_files: List[Path]) -> bool:
    """Run specific test files using unittest framework.

    Args:
      test_files: List of specific test file paths to run

    Returns:
      True if all tests passed, False otherwise
    """
    if not test_files:
        return True

    for test_file in test_files:
        if not test_file.exists():
            print(f"❌ Test file does not exist: {test_file}")
            return False
        if not test_file.is_file():
            print(f"❌ Test path is not a file: {test_file}")
            return False

    print(f"Running {len(test_files)} specific test file(s)")

    overall_success = True

    # Run unittest files individually
    print("\n📋 Running unittest files...")
    project_root = get_repo_root()
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    for test_file in test_files:
        print(f"\n  Running {test_file.name}...")
        # Load and run individual unittest file
        loader = _build_loader()
        try:
            module_name = test_file.stem
            spec = importlib.util.spec_from_file_location(module_name, test_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                suite = loader.loadTestsFromModule(module)
                if not run_test_suite(suite):
                    overall_success = False
            else:
                print(f"❌ Could not load module from {test_file}")
                overall_success = False
        except Exception as e:
            print(f"❌ Error loading {test_file}: {e}")
            overall_success = False

    return overall_success


def validate_test_directory(test_directory: Path) -> bool:
    """Quick sanity‑check that *test_directory* is a valid test root."""
    return test_directory.is_dir() and any(test_directory.glob(TEST_FILE_PATTERN))


# --------------------------------------------------------------------------- #
# CLI entry‑point                                                             #
# --------------------------------------------------------------------------- #


def main() -> int:  # noqa: D401 – imperative is fine
    parser = argparse.ArgumentParser(
        description="Run Python tests using the unittest framework."
    )
    parser.add_argument(
        "test_paths",
        nargs="*",
        default=["ossfuzz_py/unittests"],
        help="Test directories or specific test files (relative to repo root).",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--files",
        "-f",
        action="store_true",
        help="Treat test_paths as specific files instead of " "directories",
    )

    args = parser.parse_args()
    if args.verbose:
        print(f"CLI test paths: {args.test_paths}")
        print(f"Files mode: {args.files}")

    repo_root = get_repo_root()
    overall_success = True

    if args.files:
        # Run specific test files
        test_files = []
        for raw_path in args.test_paths:
            test_path = Path(raw_path)
            if not test_path.is_absolute():
                test_path = repo_root / test_path
            test_path = test_path.resolve()
            test_files.append(test_path)

        print("\n" + "=" * 60)
        print(f"Running specific test files: {[f.name for f in test_files]}")
        print("=" * 60)

        if not run_specific_test_files(test_files):
            overall_success = False
    else:
        # Run test directories (original behavior)
        for raw_dir in args.test_paths:
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
