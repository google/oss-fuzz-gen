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
Comprehensive unit tests for ossfuzz_py.core.ossfuzz_manager module.

This test suite thoroughly tests the OSSFuzzManager class including:
- Initialization with different configurations
- Repository cloning and management
- Project discovery and configuration parsing
- Error handling and edge cases
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from ossfuzz_py import OSSFuzzManager, OSSFuzzManagerError

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import directly to avoid circular import issues
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ossfuzz_py" / "core"))


class TestOSSFuzzManagerInit(unittest.TestCase):
    """Test OSSFuzzManager initialization."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

    def test_init_with_custom_checkout_path(self):
        """Test initialization with custom checkout path."""
        custom_path = self.test_dir / "custom_oss_fuzz"

        with patch("pathlib.Path.mkdir"):
            manager = OSSFuzzManager(checkout_path=custom_path, use_temp=False)

            self.assertFalse(manager.clean_up_on_exit)
            self.assertEqual(manager.checkout_path, custom_path)

    @patch("pathlib.Path.cwd")
    def test_init_with_default_path(self, mock_cwd):
        """Test initialization with default path."""
        mock_cwd.return_value = self.test_dir

        with patch("pathlib.Path.mkdir"):
            manager = OSSFuzzManager()

            expected_checkout = self.test_dir / "oss-fuzz"
            self.assertEqual(manager.checkout_path, expected_checkout)


class TestOSSFuzzManagerClone(unittest.TestCase):
    """Test OSSFuzzManager clone functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        with patch("pathlib.Path.mkdir"):
            self.manager = OSSFuzzManager(checkout_path=self.test_dir / "oss-fuzz")

    def test_clone_repository_already_exists(self):
        """Test clone when repository already exists."""
        # Create the checkout directory
        self.manager.checkout_path.mkdir(parents=True, exist_ok=True)

        with patch.object(self.manager.logger, "info") as mock_log:
            result = self.manager.clone()

            self.assertTrue(result)
            mock_log.assert_called_with(
                "Repository already exists at %s", self.manager.checkout_path
            )

    @patch("subprocess.run")
    def test_clone_successful(self, mock_run):
        """Test successful repository clone."""
        mock_run.return_value = Mock(returncode=0)

        with patch.object(self.manager.logger, "info") as mock_log:
            result = self.manager.clone()

            self.assertTrue(result)
            expected_cmd = [
                "git",
                "clone",
                "--branch",
                "master",
                "https://github.com/google/oss-fuzz.git",
                str(self.manager.checkout_path),
            ]
            mock_run.assert_called_once_with(
                expected_cmd, capture_output=True, text=True, check=True
            )
            mock_log.assert_called_with(
                "Successfully cloned OSS-Fuzz repository to %s",
                self.manager.checkout_path,
            )

    @patch("subprocess.run")
    def test_clone_subprocess_error(self, mock_run):
        """Test clone with subprocess error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="Permission denied"
        )

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.clone()

        self.assertIn(
            "Failed to clone repository: Permission denied", str(context.exception)
        )

    @patch("subprocess.run")
    def test_clone_unexpected_error(self, mock_run):
        """Test clone with unexpected error."""
        mock_run.side_effect = Exception("Network error")

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.clone()

        self.assertIn(
            "Unexpected error during clone: Network error", str(context.exception)
        )


class TestOSSFuzzManagerProjectOperations(unittest.TestCase):
    """Test OSSFuzzManager project-related operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        # Create mock repository structure
        self.checkout_path = self.test_dir / "oss-fuzz"
        self.projects_dir = self.checkout_path / "projects"
        self.projects_dir.mkdir(parents=True)

        with patch("pathlib.Path.mkdir"):
            self.manager = OSSFuzzManager(checkout_path=self.checkout_path)

    def test_get_project_path_success(self):
        """Test successful project path retrieval."""
        project_name = "test_project"
        project_path = self.projects_dir / project_name
        project_path.mkdir()

        result = self.manager.get_project_path(project_name)
        self.assertEqual(result, project_path)

    def test_get_project_path_repo_not_found(self):
        """Test get_project_path when repository doesn't exist."""
        # Remove the checkout path
        shutil.rmtree(self.checkout_path)

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.get_project_path("test_project")

        self.assertEqual(str(context.exception), "OSS-Fuzz repository not found")

    def test_get_project_path_project_not_found(self):
        """Test get_project_path when project doesn't exist."""
        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.get_project_path("nonexistent_project")

        self.assertEqual(
            str(context.exception), "Project 'nonexistent_project' not found"
        )


class TestOSSFuzzManagerListProjects(unittest.TestCase):
    """Test OSSFuzzManager list_projects functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        # Create mock repository structure
        self.checkout_path = self.test_dir / "oss-fuzz"
        self.projects_dir = self.checkout_path / "projects"
        self.projects_dir.mkdir(parents=True)

        with patch("pathlib.Path.mkdir"):
            self.manager = OSSFuzzManager(checkout_path=self.checkout_path)

    def test_list_projects_repo_not_found(self):
        """Test list_projects when repository doesn't exist."""
        shutil.rmtree(self.checkout_path)

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.list_projects()

        self.assertEqual(str(context.exception), "OSS-Fuzz repository not found")

    def test_list_projects_projects_dir_not_found(self):
        """Test list_projects when projects directory doesn't exist."""
        shutil.rmtree(self.projects_dir)

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.list_projects()

        self.assertIn(
            "Projects directory not found in repository", str(context.exception)
        )

    def test_list_projects_success_no_filter(self):
        """Test successful project listing without language filter."""
        # Create test projects
        (self.projects_dir / "project1").mkdir()
        (self.projects_dir / "project1" / "project.yaml").touch()

        (self.projects_dir / "project2").mkdir()
        (self.projects_dir / "project2" / "Dockerfile").touch()

        (self.projects_dir / ".hidden").mkdir()  # Should be ignored
        (self.projects_dir / "invalid_project").mkdir()  # No yaml or Dockerfile

        with patch.object(self.manager.logger, "debug"):
            result = self.manager.list_projects()

        self.assertEqual(sorted(result), ["project1", "project2"])

    @patch.object(OSSFuzzManager, "get_project_language")
    def test_list_projects_with_language_filter(self, mock_get_language):
        """Test project listing with language filter."""
        # Create test projects
        (self.projects_dir / "cpp_project").mkdir()
        (self.projects_dir / "cpp_project" / "project.yaml").touch()

        (self.projects_dir / "python_project").mkdir()
        (self.projects_dir / "python_project" / "project.yaml").touch()

        # Mock language detection
        def mock_language_side_effect(project_name):
            if project_name == "cpp_project":
                return "c++"
            if project_name == "python_project":
                return "python"
            return "unknown"

        mock_get_language.side_effect = mock_language_side_effect

        result = self.manager.list_projects(language="python")
        self.assertEqual(result, ["python_project"])

    def test_list_projects_exception_handling(self):
        """Test list_projects exception handling."""
        # Mock the projects_dir.iterdir method to raise an exception
        with patch(
            "pathlib.Path.iterdir", side_effect=PermissionError("Access denied")
        ):
            with self.assertRaises(OSSFuzzManagerError) as context:
                self.manager.list_projects()

            self.assertIn(
                "Project listing failed: Access denied", str(context.exception)
            )


class TestOSSFuzzManagerProjectConfig(unittest.TestCase):
    """Test OSSFuzzManager project configuration functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        # Create mock repository structure
        self.checkout_path = self.test_dir / "oss-fuzz"
        self.projects_dir = self.checkout_path / "projects"
        self.projects_dir.mkdir(parents=True)

        with patch("pathlib.Path.mkdir"):
            self.manager = OSSFuzzManager(checkout_path=self.checkout_path)

    def test_get_project_config_with_yaml(self):
        """Test get_project_config with existing project.yaml."""
        project_name = "test_project"
        project_path = self.projects_dir / project_name
        project_path.mkdir()

        config_data = {
            "homepage": "https://example.com",
            "language": "c++",
            "main_repo": "https://github.com/example/repo.git",
            "sanitizers": ["address", "memory"],
        }

        config_file = project_path / "project.yaml"
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        result = self.manager.get_project_config(project_name)
        self.assertEqual(result, config_data)

    @patch.object(OSSFuzzManager, "get_project_language")
    @patch.object(OSSFuzzManager, "get_project_repository")
    def test_get_project_config_without_yaml(self, mock_get_repo, mock_get_lang):
        """Test get_project_config without project.yaml."""
        project_name = "test_project"
        project_path = self.projects_dir / project_name
        project_path.mkdir()

        mock_get_lang.return_value = "python"
        mock_get_repo.return_value = "https://github.com/example/repo.git"

        result = self.manager.get_project_config(project_name)

        expected = {
            "project_name": project_name,
            "language": "python",
            "main_repo": "https://github.com/example/repo.git",
        }
        self.assertEqual(result, expected)

    def test_get_project_config_empty_yaml(self):
        """Test get_project_config with empty project.yaml."""
        project_name = "test_project"
        project_path = self.projects_dir / project_name
        project_path.mkdir()

        config_file = project_path / "project.yaml"
        config_file.write_text("")  # Empty file

        result = self.manager.get_project_config(project_name)
        self.assertEqual(result, {})

    @patch.object(OSSFuzzManager, "get_project_path")
    def test_get_project_config_exception_handling(self, mock_get_path):
        """Test get_project_config exception handling."""
        mock_get_path.side_effect = Exception("File read error")

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.get_project_config("test_project")

        self.assertIn(
            "Failed to get project config: File read error", str(context.exception)
        )

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_repository(self, mock_get_config):
        """Test get_project_repository method."""
        mock_get_config.return_value = {
            "main_repo": "https://github.com/example/repo.git"
        }

        result = self.manager.get_project_repository("test_project")
        self.assertEqual(result, "https://github.com/example/repo.git")

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_repository_no_repo(self, mock_get_config):
        """Test get_project_repository when no repo in config."""
        mock_get_config.return_value = {"language": "c++"}

        result = self.manager.get_project_repository("test_project")
        self.assertEqual(result, "")

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_repository_exception(self, mock_get_config):
        """Test get_project_repository exception handling."""
        mock_get_config.side_effect = Exception("Config error")

        result = self.manager.get_project_repository("test_project")
        self.assertEqual(result, "")

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_language(self, mock_get_config):
        """Test get_project_language method."""
        mock_get_config.return_value = {"language": "python"}

        result = self.manager.get_project_language("test_project")
        self.assertEqual(result, "python")

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_language_default(self, mock_get_config):
        """Test get_project_language with default value."""
        mock_get_config.return_value = {"main_repo": "https://example.com"}

        result = self.manager.get_project_language("test_project")
        self.assertEqual(result, "c++")

    @patch.object(OSSFuzzManager, "get_project_config")
    def test_get_project_language_exception(self, mock_get_config):
        """Test get_project_language exception handling."""
        mock_get_config.side_effect = Exception("Config error")

        result = self.manager.get_project_language("test_project")
        self.assertEqual(result, "c++")


class TestOSSFuzzManagerRepositoryOperations(unittest.TestCase):
    """Test OSSFuzzManager repository operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        self.checkout_path = self.test_dir / "oss-fuzz"
        self.checkout_path.mkdir(parents=True)

        with patch("pathlib.Path.mkdir"):
            self.manager = OSSFuzzManager(checkout_path=self.checkout_path)

    def test_update_repository_repo_not_found(self):
        """Test update_repository when repository doesn't exist."""
        shutil.rmtree(self.checkout_path)

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.update_repository()

        self.assertEqual(str(context.exception), "OSS-Fuzz repository not found")

    @patch("subprocess.run")
    def test_update_repository_success(self, mock_run):
        """Test successful repository update."""
        mock_run.return_value = Mock(returncode=0)

        with patch.object(self.manager.logger, "info") as mock_log:
            result = self.manager.update_repository()

        self.assertTrue(result)
        mock_run.assert_called_once_with(
            ["git", "pull"],
            cwd=self.checkout_path,
            capture_output=True,
            text=True,
            check=True,
        )
        mock_log.assert_called_with("Successfully updated OSS-Fuzz repository")

    @patch("subprocess.run")
    def test_update_repository_subprocess_error(self, mock_run):
        """Test update_repository with subprocess error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="Merge conflict"
        )

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.update_repository()

        self.assertIn(
            "Failed to update repository: Merge conflict", str(context.exception)
        )

    @patch("subprocess.run")
    def test_update_repository_unexpected_error(self, mock_run):
        """Test update_repository with unexpected error."""
        mock_run.side_effect = Exception("Network timeout")

        with self.assertRaises(OSSFuzzManagerError) as context:
            self.manager.update_repository()

        self.assertIn(
            "Unexpected error during update: Network timeout", str(context.exception)
        )


class TestOSSFuzzManagerCleanup(unittest.TestCase):
    """Test OSSFuzzManager cleanup functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

    @patch("shutil.rmtree")
    def test_postprocess_cleanup_enabled(self, mock_rmtree):
        """Test postprocess with cleanup enabled."""
        with patch("pathlib.Path.mkdir"), patch(
            "tempfile.mkdtemp", return_value=str(self.test_dir)
        ):
            manager = OSSFuzzManager(use_temp=True)
            manager.temp_dir = self.test_dir

            with patch.object(manager.logger, "info") as mock_log:
                result = manager.postprocess()

            self.assertTrue(result)
            mock_rmtree.assert_called_once_with(self.test_dir)
            mock_log.assert_called_with("Cleaned up temporary files")

    def test_postprocess_cleanup_disabled(self):
        """Test postprocess with cleanup disabled."""
        with patch("pathlib.Path.mkdir"):
            manager = OSSFuzzManager(checkout_path=self.test_dir / "oss-fuzz")

            result = manager.postprocess()
            self.assertTrue(result)

    @patch("shutil.rmtree")
    def test_postprocess_cleanup_error(self, mock_rmtree):
        """Test postprocess with cleanup error."""
        mock_rmtree.side_effect = PermissionError("Access denied")

        with patch("pathlib.Path.mkdir"), patch(
            "tempfile.mkdtemp", return_value=str(self.test_dir)
        ):
            manager = OSSFuzzManager(use_temp=True)
            manager.temp_dir = self.test_dir

            with patch.object(manager.logger, "warning"):
                result = manager.postprocess()

            self.assertFalse(result)


class TestOSSFuzzManagerIntegration(unittest.TestCase):
    """Integration tests for OSSFuzzManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

    @patch("subprocess.run")
    def test_full_workflow_temp_directory(self, mock_run):
        """Test full workflow using temporary directory."""
        mock_run.return_value = Mock(returncode=0)

        with patch("tempfile.mkdtemp", return_value=str(self.test_dir)):
            # Initialize manager (don't patch mkdir for this test)
            manager = OSSFuzzManager(use_temp=True)

            # Clone repository
            result = manager.clone()
            self.assertTrue(result)

            # Create mock project structure
            projects_dir = manager.checkout_path / "projects"
            projects_dir.mkdir(parents=True, exist_ok=True)

            test_project = projects_dir / "test_project"
            test_project.mkdir(parents=True, exist_ok=True)

            config_data = {"language": "python", "main_repo": "https://example.com"}
            config_file = test_project / "project.yaml"
            with open(config_file, "w") as f:
                yaml.dump(config_data, f)

            # Test project operations
            projects = manager.list_projects()
            self.assertIn("test_project", projects)

            config = manager.get_project_config("test_project")
            self.assertEqual(config["language"], "python")

            # Test cleanup
            result = manager.postprocess()
            self.assertTrue(result)


class TestOSSFuzzManagerRealExecution(unittest.TestCase):
    """Real execution tests for OSSFuzzManager (no mocking of subprocess)."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.test_dir, ignore_errors=True))

        # Configure logging to show all logs
        import logging

        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            force=True,
        )

    def test_real_oss_fuzz_clone_shallow(self):
        """Test real OSS-Fuzz repository clone and management operations."""
        # Skip if git is not available
        try:
            subprocess.run(["git", "--version"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.skipTest("Git not available")

        checkout_path = self.test_dir / "oss-fuzz-real"
        manager = OSSFuzzManager(checkout_path=checkout_path, use_temp=True)

        def shallow_clone(version="master"):
            try:
                if manager.checkout_path.exists():
                    manager.logger.info(
                        f"Repository already exists at {manager.checkout_path}"
                    )
                    return True

                repo_url = "https://github.com/google/oss-fuzz.git"
                cmd = [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    version,
                    repo_url,
                    str(manager.checkout_path),
                ]
                subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=60
                )
                manager.logger.info(
                    "Successfully cloned OSS-Fuzz repository to %s",
                    manager.checkout_path,
                )
                return True

            except subprocess.TimeoutExpired:
                error_msg = "Clone operation timed out"
                manager.logger.error(error_msg)
                raise OSSFuzzManagerError(error_msg)
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to clone repository: {e.stderr}"
                manager.logger.error(error_msg)
                raise OSSFuzzManagerError(error_msg)
            except Exception as e:
                error_msg = f"Unexpected error during clone: {str(e)}"
                manager.logger.error(error_msg)
                raise OSSFuzzManagerError(error_msg)

        manager.clone = shallow_clone

        # Test repository operations
        self.assertTrue(manager.clone())
        self.assertTrue(manager.checkout_path.exists())
        self.assertTrue((manager.checkout_path / "projects").exists())
        self.assertTrue((manager.checkout_path / "infra").exists())

        # Test repository update
        try:
            self.assertTrue(manager.update_repository())
        except OSSFuzzManagerError as e:
            self.skipTest(f"Repository update failed: {str(e)}")

        # Test project listing and filtering
        all_projects = manager.list_projects()
        self.assertGreater(len(all_projects), 0)
        self.assertIsInstance(all_projects, list)

        # Test language filtering (try common languages)
        for lang in ["c++", "python", "go", "rust"]:
            lang_projects = manager.list_projects(language=lang)
            self.assertIsInstance(lang_projects, list)
            # Verify filtered projects are subset of all projects
            self.assertTrue(all(p in all_projects for p in lang_projects))

        # Test project configuration operations
        if all_projects:
            # Test valid project
            first_project = all_projects[0]
            config = manager.get_project_config(first_project)
            self.assertIsInstance(config, dict)
            self.assertTrue(
                any(key in config for key in ["language", "main_repo", "homepage"])
            )

            # Get and verify project language
            lang = manager.get_project_language(first_project)
            self.assertIsInstance(lang, str)
            self.assertNotEqual(lang, "")

            # Get and verify project repository
            repo = manager.get_project_repository(first_project)
            self.assertIsInstance(repo, str)

        # Test error cases
        with self.assertRaises(OSSFuzzManagerError):
            manager.get_project_path("nonexistent_project_123456789")

        # Test cleanup
        self.assertTrue(manager.postprocess())
        if manager.clean_up_on_exit:
            self.assertFalse(manager.temp_dir.exists())


if __name__ == "__main__":
    unittest.main()
