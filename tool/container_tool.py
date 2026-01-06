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
"""A tool for LLM agents to interact within a project's docker container."""
import logging
import os
import subprocess as sp
import time
from typing import Optional

from experiment import oss_fuzz_checkout
from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from tool.base_tool import BaseTool

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
"""
Workflow: 
Initialization:
- Copy oss-fuzz dir on host machine into specially named dir. The container will reuse this throughout its lifetime
- self.generated_project_path holds this local path

Execution Stage:
- Write fuzz driver to container (similar to OnePromptPrototyper)
- Write build script to container if necessary 
- Run the driver with infra/helper.py
"""


class ProjectContainerTool(BaseTool):
    """A tool for LLM agents to interact within a project's docker container."""

    def __init__(
        self, benchmark: Benchmark, name: str = "", project_name: str = ""
    ) -> None:
        super().__init__(benchmark, name)
        self.project_name = project_name or benchmark.project
        self.image_name = self._prepare_project_image(self.project_name)
        self.generated_oss_fuzz_name = os.path.basename(self.image_name)
        self.generated_project_path = os.path.join(
            oss_fuzz_checkout.OSS_FUZZ_DIR, "projects", self.generated_oss_fuzz_name
        )
        self.vmap_outdir = get_build_artifact_dir(self.generated_oss_fuzz_name, "out")
        self.vmap_workdir = get_build_artifact_dir(self.generated_oss_fuzz_name, "work")
        self.container_id = self._start_docker_container()
        self._setup_container_env()
        self.build_script_path = "/src/build.sh"
        self._backup_default_build_script()
        self.project_dir = self._get_project_dir()

    def tutorial(self) -> str:
        """Constructs a tool guide tutorial for LLM agents."""
        return self._get_tutorial_file_content("container_tool.txt").replace(
            "{FUZZ_TARGET_PATH}", self.benchmark.target_path
        )

    def _setup_container_env(self):
        """Alias mkdir to mkdir -p so we can reuse build artifacts"""
        command = """cat > /etc/profile.d/mkdir.sh <<'EOF'
mkdir() { command mkdir -p "$@"; }
export -f mkdir
EOF"""
        self.execute(command)

    def _prepare_project_image(self, project_name: str) -> str:
        """Prepares the project's OSS-Fuzz docker image and returns the image name."""
        image_name = oss_fuzz_checkout.prepare_project_image_by_name(project_name)
        if image_name:
            return image_name
        raise Exception(f"Failed to build image for {project_name}")
        # image_name = oss_fuzz_checkout.prepare_project_image(
        #     self.benchmark, project_name)
        # if image_name:
        #   return image_name
        # raise Exception(f"Failed to build image for {project_name}")

    def _execute_command_in_container(
        self, command: list[str], log_path: Optional[str] = None
    ) -> sp.CompletedProcess:
        """Executes the |command| in subprocess and log output."""
        log_file = sp.PIPE
        if log_path is not None:
            log_file = open(log_path, "w+")
        try:
            result = sp.run(
                command,
                stdout=log_file,
                stderr=sp.PIPE,
                check=False,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if log_path is not None:
                output = f"Logged in {log_path}"
            else:
                output = result.stdout
            logger.debug(
                "Executing command (%s) in container %s: Return code %d. STDOUT: %s, "
                "STDERR: %s",
                command,
                self.container_id,
                result.returncode,
                output,
                result.stderr,
            )
            return result
        except Exception as e:
            logger.error(
                "Executing command (%s) in container failed with Exception: %s",
                command,
                e,
            )
            return sp.CompletedProcess(command, returncode=1, stdout="", stderr="")
        finally:
            if log_path is not None:
                log_file.close()

    def _execute_command(self, command: list[str]) -> sp.CompletedProcess:
        """Executes the |command| in subprocess and log output."""
        try:
            result = sp.run(
                command,
                stdout=sp.PIPE,
                stderr=sp.PIPE,
                check=False,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )

            logger.debug(
                "Executing command (%s): Return code %d. STDOUT: %s, STDERR: %s",
                command,
                result.returncode,
                result.stdout,
                result.stderr,
            )
            return result
        except Exception as e:
            logger.error("Executing command (%s) failed with Exception: %s", command, e)
            return sp.CompletedProcess(command, returncode=1, stdout="", stderr="")

    def _backup_default_build_script(self) -> None:
        """Creates a copy of the human-written /src/build.sh for LLM to use."""
        backup_command = f"cp {self.build_script_path} /src/build.bk.sh"
        process = self.execute(backup_command)
        if process.returncode:
            logger.error(
                "Failed to create a backup of %s: %s",
                self.build_script_path,
                self.image_name,
            )

    def _get_project_dir(self) -> str:
        """Returns the project-under-test's source code directory."""
        pwd_command = "pwd"
        process = self.execute(pwd_command)
        if process.returncode:
            logger.error("Failed to get the WORKDIR: %s", self.image_name)
            return ""
        return process.stdout.strip()

    def _start_docker_container(self) -> str:
        """Runs the project's OSS-Fuzz image as a background container and returns
        the container ID."""
        command = [
            "docker",
            "run",
            "-d",
            "--privileged",
            "--shm-size=2g",
            "--platform",
            "linux/amd64",
            "-t",
            "-e",
            "FUZZING_ENGINE=libfuzzer",
            "-e",
            "ARCHITECTURE=x86_64",
            "-e",
            f"PROJECT_NAME={self.generated_oss_fuzz_name}",
            "-e",
            f"FUZZING_LANGUAGE={self.benchmark.language}",
            "-e",
            "ASAN_OPTIONS=detect_leaks=0",
            "-v",
            f"{self.vmap_outdir}:/out",
            "-v",
            f"{self.vmap_workdir}:/work",
            "--entrypoint=/bin/bash",
            f"gcr.io/oss-fuzz/{self.generated_oss_fuzz_name}",
        ]
        os.makedirs(self.vmap_outdir, exist_ok=True)
        os.makedirs(self.vmap_workdir, exist_ok=True)
        result = self._execute_command(command)
        if result.returncode:
            logger.error("Failed to start container of image: %s", self.image_name)
        container_id = result.stdout.strip()
        return container_id

    def execute(
        self, command: str, log_path: Optional[str] = None
    ) -> sp.CompletedProcess:
        """Executes the |command| in the container and returns the output."""
        logger.debug("Executing command (%s) in %s: ", command, self.container_id)
        execute_command_in_container = [
            "docker",
            "exec",
            self.container_id,
            "/bin/bash",
            "-c",
            command,
        ]
        process = self._execute_command_in_container(
            execute_command_in_container, log_path
        )
        process.args = command
        return process

    def compile(
        self,
        extra_commands: str = "",
        sanitizer: str = "",
        log_path: Optional[str] = None,
    ) -> sp.CompletedProcess:
        """Compiles the fuzz target."""
        mkdir_alias = "source /etc/profile.d/mkdir.sh; "
        command = "compile > /dev/null" + extra_commands
        if sanitizer:
            command = f"SANITIZER={sanitizer} " + command
        begin_time = time.time()
        compile_process = self.execute(mkdir_alias + command, log_path)
        end_time = time.time()
        # Hide Compilation command so that LLM won't reuse it in the inspection tool
        # and be distracted by irrelevant errors, e.g., `build/ already exits`.
        compile_process.args = "# Compiles the fuzz target."
        logger.info(
            "**** Container %s: Compiled reusable container with sanitizer %s in %.4f seconds****",
            self.container_id,
            sanitizer,
            end_time - begin_time,
        )
        return compile_process

    def fuzz(self, workdirs: WorkDirs, run_timeout: int, log_path: str) -> None:
        logger.info("**** Fuzzing with reusable container ****")
        corpus_dir = workdirs.corpus(self.benchmark.target_name)
        command = [
            "python3",
            "infra/helper.py",
            "run_fuzzer",
            "--corpus-dir",
            corpus_dir,
            self.generated_oss_fuzz_name,
            self.benchmark.target_name,
            "--",
        ] + _libfuzzer_args(run_timeout)

        with open(log_path, "w") as f:
            proc = sp.Popen(
                command,
                stdin=sp.DEVNULL,
                stdout=f,
                stderr=sp.STDOUT,
                cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
            )
            logger.debug("RUNNING COMMAND: %s", " ".join(command))
            # TODO(ochang): Handle the timeout exception.
            try:
                proc.wait(timeout=run_timeout + 5)
            except sp.TimeoutExpired:
                logger.info("%s timed out during fuzzing.", self.generated_project_path)
                # Try continuing and parsing the logs even in case of timeout.
        if proc.returncode != 0:
            logger.info(
                "********** Failed to run %s. **********", self.generated_project_path
            )
            logger.info("OUTPUT: %s", open(log_path, "r").read())
        else:
            logger.info("Successfully run %s.", self.generated_project_path)

    def get_coverage(self, workdirs: WorkDirs) -> None:
        """Allocate two minutes for coverage collection"""
        logger.info("**** Getting coverage with reusable container ****")
        corpus_dir = workdirs.corpus(self.benchmark.target_name)
        command = [
            "python3",
            "infra/helper.py",
            "coverage",
            "--corpus-dir",
            corpus_dir,
            "--fuzz-target",
            self.benchmark.target_name,
            "--port",
            "",
            "--no-serve",
            self.generated_oss_fuzz_name,
        ]
        logger.debug("RUNNING COMMAND: %s", " ".join(command))
        try:
            sp.run(
                command,
                capture_output=True,
                cwd=oss_fuzz_checkout.OSS_FUZZ_DIR,
                stdin=sp.DEVNULL,
                check=True,
                timeout=120,
            )
        except sp.TimeoutExpired as e:
            logger.info(
                "Coverage timed out for %s:\n%s\n%s",
                self.generated_oss_fuzz_name,
                e.stdout,
                e.stderr,
            )
        except sp.CalledProcessError as e:
            logger.info(
                "Failed to generate coverage for %s:\n%s\n%s",
                self.generated_oss_fuzz_name,
                e.stdout,
                e.stderr,
            )

    def terminate(self) -> bool:
        """Terminates and removes the container."""
        # For testing purposes, don't do anything
        return True
        # terminate_container_command = ["docker", "stop", self.container_id]
        # result = self._execute_command(terminate_container_command)
        # if result:
        #   return result
        # remove_container_command = ["docker", "rm", self.container_id]
        # result = self._execute_command(remove_container_command)
        # remove_image_command = ["docker", "rmi", self.image_name]
        # result = self._execute_command(remove_image_command)
        # return result.returncode == 0

    def rewrite_driver(self, content: str) -> None:
        self.write_to_file(content, self.benchmark.target_path)

    def rewrite_build_script(self, content: str) -> None:
        self.write_to_file(content, "/src/build.sh")

    def write_to_file(self, content: str, file_path: str) -> None:
        replace_file_content_command = (
            f'cat << "OFG_EOF" > {file_path}\n{content}\nOFG_EOF'
        )
        self.execute(replace_file_content_command)


def get_build_artifact_dir(generated_project: str, build_artifact: str) -> str:
    """
    Returns the |build_artifact| absolute directory path for |generated_project|.
    """
    return os.path.join(
        oss_fuzz_checkout.OSS_FUZZ_DIR, "build", build_artifact, generated_project
    )


def _libfuzzer_args(run_timeout: int) -> list[str]:
    return [
        "-print_final_stats=1",
        f"-max_total_time={run_timeout}",
        # Without this flag, libFuzzer only consider short inputs in short
        # experiments, which lowers the coverage for quick performance tests.
        "-len_control=0",
        # Timeout per testcase.
        "-timeout=30",
        "-detect_leaks=0",
    ]
