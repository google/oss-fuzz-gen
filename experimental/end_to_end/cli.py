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
"""Create OSS-Fuzz projects from scratch."""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import requests
import yaml

from data_prep import introspector
from experimental.build_fixer import build_fix
from experimental.build_generator import runner
from llm_toolkit import models

logger = logging.getLogger(name=__name__)
LOG_FMT = (
    "%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] " ": %(funcName)s: %(message)s"
)

OFG_BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
)


def setup_workdirs(defined_dir):
    """Sets up the working directory."""

    if defined_dir:
        workdir = defined_dir
    else:
        workdir = tempfile.mkdtemp()
    logger.info("Using work directory: %s", workdir)
    os.makedirs(workdir, exist_ok=True)

    # Clone two OSS-Fuzz projects
    subprocess.check_call(
        "git clone https://github.com/google/oss-fuzz oss-fuzz-1",
        shell=True,
        cwd=workdir,
    )

    # Clone another OSS-Fuzz, for OFG core
    subprocess.check_call(
        "git clone https://github.com/google/oss-fuzz oss-fuzz", shell=True, cwd=workdir
    )
    os.mkdir(os.path.join(workdir, "oss-fuzz", "venv"))

    # Clone Fuzz Introspector
    subprocess.check_call(
        "git clone https://github.com/ossf/fuzz-introspector", shell=True, cwd=workdir
    )

    # Ensure fuzz introspector's requirements.txt is installed
    subprocess.check_call(
        "python3 -m pip install -r requirements.txt",
        shell=True,
        cwd=os.path.join(workdir, "fuzz-introspector"),
    )
    subprocess.check_call(
        "python3 -m pip install -r requirements.txt",
        shell=True,
        cwd=os.path.join(
            workdir, "fuzz-introspector", "tools", "web-fuzzing-introspection"
        ),
    )
    return workdir


def _run_introspector_collection(runner_script, project, wd, semaphore):
    """Run introspector on the given project."""
    semaphore.acquire()

    cmd = ["python3"]
    cmd.append(runner_script)  # introspector helper script
    cmd.append("introspector")  # force an introspector run
    cmd.append(project)  # target project
    cmd.append("1")  # run the harness for 1 second
    cmd.append("--disable-webserver")  # do not launch FI webapp

    try:
        logger.info("Collecting introspector information on %s", project)
        subprocess.check_call(
            " ".join(cmd),
            shell=True,
            cwd=wd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        pass
    semaphore.release()


def extract_introspector_reports_for_benchmarks(
    projects_to_run, workdir, parallel_build_jobs
):
    """Runs introspector through each report to collect program analysis data."""
    oss_fuzz_dir = os.path.join(workdir, "oss-fuzz")
    runner_script = os.path.join(
        workdir, "fuzz-introspector", "oss_fuzz_integration", "runner.py"
    )

    semaphore = threading.Semaphore(parallel_build_jobs)
    jobs = []

    for project in projects_to_run:
        proc = threading.Thread(
            target=_run_introspector_collection,
            args=(runner_script, project, oss_fuzz_dir, semaphore),
        )
        jobs.append(proc)
        proc.start()

    for proc in jobs:
        proc.join()

    # Often the terminal will become corrupted after a lot of introspector runs.
    # Call reset here to ensure we're in a safe state.
    subprocess.check_call("reset", shell=True)


def shutdown_fi_webapp():
    """Shutsdown the FI webapp if it exists."""
    try:
        subprocess.check_call(
            "curl --silent http://localhost:8080/api/shutdown", shell=True
        )
    except subprocess.CalledProcessError:
        pass


def create_fi_db(workdir):
    """Creates the FI webapp database"""
    oss_fuzz_dir = os.path.join(workdir, "oss-fuzz")

    fi_db_dir = os.path.join(
        workdir,
        "fuzz-introspector",
        "tools",
        "web-fuzzing-introspection",
        "app",
        "static",
        "assets",
        "db",
    )
    cmd = ["python3"]
    cmd.append("web_db_creator_from_summary.py")
    cmd.append("--local-oss-fuzz")
    cmd.append(oss_fuzz_dir)
    try:
        logger.info("Creating fuzz introspector database")
        subprocess.check_call(
            " ".join(cmd),
            shell=True,
            cwd=fi_db_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        logger.info("Created database successfully")
    except subprocess.CalledProcessError:
        logger.info("Failed creation of DB")


def launch_fi_webapp(workdir):
    """Launches webapp so OFG can query projects."""
    logger.info("Launching webapp")
    oss_fuzz_dir = os.path.join(workdir, "oss-fuzz")
    fi_webapp_dir = os.path.join(
        workdir, "fuzz-introspector", "tools", "web-fuzzing-introspection", "app"
    )
    environ = os.environ.copy()
    environ["FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ"] = oss_fuzz_dir
    cmd = ["python3"]
    cmd.append("main.py &")

    subprocess.check_call(
        " ".join(cmd),
        shell=True,
        cwd=fi_webapp_dir,
        env=environ,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def wait_until_fi_webapp_is_launched():
    """Return when the webapp has started"""
    logger.info("Waiting for the webapp to start")

    sec_to_wait = 10
    for _ in range(10):
        time.sleep(sec_to_wait)

        resp = requests.get("http://127.0.0.1:8080", timeout=10)
        if "Fuzzing" in resp.text:
            return
    # If this is reached then the webapp likely didn't start.
    # Exit.
    logger.info("Could not start FI webapp")
    sys.exit(0)


def run_ofg_generation(projects_to_run, workdir, args, target_benchmarks=""):
    """Runs harness generation"""
    logger.info("Running OFG experiment: %s", os.getcwd())
    oss_fuzz_dir = os.path.join(workdir, "oss-fuzz")

    cmd = ["python3", os.path.join(OFG_BASE_DIR, "run_all_experiments.py")]
    cmd.append("--model")
    cmd.append(args.model)

    if not target_benchmarks:
        cmd.append("-g")
        cmd.append(args.benchmark_oracles)
        cmd.append("-gp")
        cmd.append(",".join(projects_to_run))
        cmd.append("-gm")
        cmd.append(str(args.generate_benchmarks_max))
    else:
        cmd.append("-b")
        cmd.append(target_benchmarks)
    cmd.append("--context")
    cmd.append("-of")
    cmd.append(oss_fuzz_dir)
    cmd.append("-e")
    cmd.append("http://127.0.0.1:8080/api")
    cmd.append("-mr")
    cmd.append(str(args.max_round))
    if args.hg_agent:
        cmd.append("--agent")

    environ = os.environ.copy()

    environ["LLM_NUM_EVA"] = "4"
    environ["LLM_NUM_EXP"] = "4"
    environ["OFG_CLEAN_UP_OSS_FUZZ"] = "0"
    environ["OFG_USE_CACHING"] = "0"

    subprocess.check_call(" ".join(cmd), shell=True, env=environ)


def copy_generated_projects_to_harness_gen(out_gen, workdir):
    """Copies projects from build generation ready for harness generation."""
    projects_dir = os.path.join(out_gen, "oss-fuzz-projects")
    if not os.path.isdir(projects_dir):
        logger.info("Found no projects.")
        return set()

    # Copy projects over
    projects_to_run = []
    for project in os.listdir(projects_dir):
        dst = os.path.join(workdir, "oss-fuzz", "projects", project)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        logger.info(
            "Copying: %s :: %s",
            os.path.join(projects_dir, project),
            os.path.join(workdir, "oss-fuzz", "projects", project),
        )
        shutil.copytree(
            os.path.join(projects_dir, project),
            os.path.join(workdir, "oss-fuzz", "projects", project),
        )
        projects_to_run.append(project)
    return projects_to_run


def create_merged_oss_fuzz_projects(
    projects_to_run, workdir, merged_project_out_dir="final-oss-fuzz-projects"
) -> None:
    """Create OSS-Fuzz projects using successful harnesses."""

    logger.info(
        "Merging harnesses for the following projects: %s", str(projects_to_run)
    )
    logger.info("Writing results in %s", merged_project_out_dir)

    # Get list of projects created auto-building for.
    generated_projects = []
    for project_name in projects_to_run:
        project_yaml = os.path.join(
            workdir, "oss-fuzz", "projects", project_name, "project.yaml"
        )
        if not os.path.isfile(project_yaml):
            continue
        with open(project_yaml, "r", encoding="utf-8") as f:
            project_dict = yaml.safe_load(f)

        generated_projects.append(
            {"name": project_name, "language": project_dict["language"]}
        )

    # Iterate results and copy fuzz harnesses into dedicated project folder.
    results_dir = "results"
    if not os.path.isdir(results_dir):
        logger.info("No results identified")
        return

    for result in os.listdir(results_dir):
        # Find project name
        project = {}
        for project_gen in generated_projects:
            if result.startswith(f'output-{project_gen["name"]}'):
                project = project_gen
        if not project:
            continue

        # Copy the harness over
        # if not os.path.isdir('final-oss-fuzz-projects'):
        #  os.makedirs('final-oss-fuzz-projects')
        project_dir = os.path.join(merged_project_out_dir, project["name"])
        # if not os.path.isdir(project_dir):
        #  os.makedirs(project_dir)
        os.makedirs(project_dir, exist_ok=True)

        # Check if it was successful
        idx_to_copy = ""
        status_base = os.path.join("results", result, "status")
        for idx in sorted(os.listdir(status_base)):
            id_path = os.path.join(status_base, idx)
            if not os.path.isdir(id_path):
                continue
            result_json = os.path.join(id_path, "result.json")
            if not os.path.isfile(result_json):
                continue
            with open(result_json, "r") as f:
                json_dict = json.loads(f.read())
            if json_dict["compiles"]:
                idx_to_copy = idx
                break

        if not idx_to_copy:
            logger.info("Did not find a harness to copy")
            continue
        logger.debug("Copying idx: %s", idx_to_copy)

        # Copy over the harness
        fuzz_src = os.path.join(
            "results", result, "fuzz_targets", f"{idx_to_copy}.fuzz_target"
        )
        with open(fuzz_src, "r") as f:
            fuzz_content = f.read()
        idx = 0

        while True:
            if "extern 'C'" in fuzz_content or "std::" in fuzz_content:
                fuzz_dst = os.path.join(project_dir, f"empty-fuzzer.{idx}.cpp")
            else:
                fuzz_dst = os.path.join(project_dir, f"empty-fuzzer.{idx}.c")
            if not os.path.isfile(fuzz_dst):
                break
            idx += 1

        # Copy the harness
        build_src = os.path.join(
            workdir, "oss-fuzz", "projects", project["name"], "build.sh"
        )
        build_dst = os.path.join(project_dir, "build.sh")
        shutil.copy(build_src, build_dst)

        docker_src = os.path.join(
            workdir, "oss-fuzz", "projects", project["name"], "Dockerfile"
        )
        docker_dst = os.path.join(project_dir, "Dockerfile")
        shutil.copy(docker_src, docker_dst)

        project_yaml_src = os.path.join(
            workdir, "oss-fuzz", "projects", project["name"], "project.yaml"
        )
        project_yaml_dst = os.path.join(project_dir, "project.yaml")
        shutil.copy(project_yaml_src, project_yaml_dst)

        shutil.copy(fuzz_src, fuzz_dst)


def _create_data_dir(workdir):
    """Copy data from build generation to directory for cloud experimentation"""
    dst_dir = _get_next_data_dst_dir()
    oss_fuzz_build_out = os.path.join(workdir, "oss-fuzz", "build", "out")

    # Copy OSS-Fuzz data
    projects_to_copy = []
    out_folders = ["inspector", "report", "report_target", "textcov_reports"]
    for bp in os.listdir(oss_fuzz_build_out):
        src_project = os.path.join(oss_fuzz_build_out, bp)
        dst_project = os.path.join(dst_dir, "oss-fuzz2", "build", "out", bp)

        # Make sure all directories are there
        do_copy = True
        for out_folder in out_folders:
            if not os.path.isdir(os.path.join(src_project, out_folder)):
                do_copy = False
        if not do_copy:
            continue
        os.makedirs(dst_project, exist_ok=True)

        for out_folder in out_folders:
            shutil.copytree(
                os.path.join(src_project, out_folder),
                os.path.join(dst_project, out_folder),
            )
        projects_to_copy.append(bp)

    os.makedirs(os.path.join(dst_dir, "oss-fuzz2", "projects"), exist_ok=True)

    for project in projects_to_copy:
        p_src = os.path.join(workdir, "oss-fuzz", "projects", project)
        p_dst = os.path.join(dst_dir, "oss-fuzz2", "projects", project)
        shutil.copytree(p_src, p_dst)

    # Copy Fuzz Introspector data
    fuzz_introspector_db_folder = os.path.join(
        workdir,
        "fuzz-introspector",
        "tools",
        "web-fuzzing-introspection",
        "app",
        "static",
        "assets",
        "db",
    )
    shutil.copytree(
        fuzz_introspector_db_folder, os.path.join(dst_dir, "fuzz_introspector_db")
    )

    # Delete .gitignore that may exist in the DB folder. We do this because the
    # files are needed when uploaded to OFG.
    gitignore_file = os.path.join(dst_dir, "fuzz_introspector_db", ".gitignore")
    if os.path.isfile(gitignore_file):
        os.remove(gitignore_file)

    return dst_dir


def prepare_fuzz_introspector_db(out_gen, workdir, parallel_introspector_jobs):
    # Run introspector collection on the generated projects
    projects_to_run = copy_generated_projects_to_harness_gen(out_gen, workdir)
    extract_introspector_reports_for_benchmarks(
        projects_to_run, workdir, parallel_introspector_jobs
    )

    # Create a fuzz introspector database based on the projects in
    # the working directory's OSS-Fuzz.
    shutdown_fi_webapp()
    create_fi_db(workdir)


def run_harness_generation(workdir, args, target_project="", target_function=""):
    """Runs harness generation based on the projects in `out_gen`"""

    # Read the json file from FI to get all current projects.
    fi_project_json = os.path.join(
        workdir,
        "fuzz-introspector",
        "tools",
        "web-fuzzing-introspection",
        "app",
        "static",
        "assets",
        "db",
        "all-project-current.json",
    )
    if not os.path.isfile(fi_project_json):
        logger.info("Did not find FI DB file.")
        set()

    projects_to_run = []
    if target_project:
        projects_to_run = [target_project]
    else:
        with open(fi_project_json, "r") as f:
            json_content = json.load(f)
        for elem in json_content:
            projects_to_run.append(elem["project_name"])

    # Launch the fuzz introspector webapp so it's ready for OFG core
    shutdown_fi_webapp()
    launch_fi_webapp(workdir)
    wait_until_fi_webapp_is_launched()
    dst_data_dir = _create_data_dir(workdir)
    logger.info("Wrote data directory for OFG experiments in %s", dst_data_dir)

    # Generate benchmarks if asked to
    if target_project and target_function:
        logger.info("Generating benchmark for specific function")
        introspector.set_introspector_endpoints("http://127.0.0.1:8080/api")
        benchmark_dir = introspector.generate_benchmark_for_targeted_function(
            target_project, target_function
        )
        if not benchmark_dir:
            logger.info("Failed to generated benchmarks.")
            sys.exit(1)
    else:
        logger.info("Generating a broad set of benchmarks")
        benchmark_dir = ""

    # Run OFG core using local OSS-Fuzz and local Fuzz Introspector.
    run_ofg_generation(projects_to_run, workdir, args, benchmark_dir)

    create_merged_oss_fuzz_projects(projects_to_run, workdir)
    return projects_to_run


def setup_logging():
    """Initiate logging."""
    logging.basicConfig(level=logging.DEBUG, format=LOG_FMT)


def _get_next_folder_in_idx(base_name):
    """Get next pre-named work directory."""
    idx = 0
    while True:
        if not os.path.isdir(f"{base_name}-{idx}"):
            break
        idx += 1
    return f"{base_name}-{idx}"


def get_next_out_folder():
    """Get next pre-named work directory."""
    return _get_next_folder_in_idx("generated-projects")


def _get_next_data_dst_dir():
    """Gets next data dir"""
    return _get_next_folder_in_idx("data-dir")


def _run_build_generation(workdir, out_folder, args):
    """Build script generation."""
    oss_fuzz_dir = os.path.join(workdir, "oss-fuzz-1")
    target_repositories = runner.extract_target_repositories(args.input)
    if args.build_generation_mode == "agent":
        # Prepare arguments used deeper in OFG core.
        # TODO(David) make this cleaner.
        args.oss_fuzz = oss_fuzz_dir
        args.work_dirs = "work_dirs"
        runner.run_agent(target_repositories, args)
    elif args.build_generation_mode == "template-based":
        runner.run_parallels(
            os.path.abspath(oss_fuzz_dir),
            target_repositories,
            args.model,
            "all",
            out_folder,
            parallel_jobs=args.build_jobs,
            max_timeout=args.build_timeout,
        )
    else:
        logger.info("Unknown build generation mode: %s", args.build_generation_mode)
        sys.exit(1)


def run_fuzz_introspector_db_creation(workdir, generated_builds, parallel_build_jobs):
    """Entrypoint for fuzz introspector database creation."""

    workdir = os.path.abspath(workdir)

    # Create working directory if it doesn't exist.
    if not os.path.isdir(workdir):
        workdir = setup_workdirs(workdir)
    prepare_fuzz_introspector_db(generated_builds, workdir, parallel_build_jobs)


def run_build_generation(args):
    """Generates builds and harnesses for repositories in input."""

    # Prepare working directory.
    workdir = setup_workdirs(args.workdir)

    abs_workdir = os.path.abspath(workdir)
    if not args.out:
        out_folder = get_next_out_folder()
    else:
        out_folder = args.out

    _run_build_generation(abs_workdir, out_folder, args)


def run_cmd_fix_build(args):
    """Command entrypoint for fixing OSS-Fuzz build scripts."""
    workdir = setup_workdirs(None)
    abs_workdir = os.path.abspath(workdir)
    oss_fuzz_dir = os.path.join(abs_workdir, "oss-fuzz")
    args.work_dirs = "work_dirs"
    build_fix.fix_build(args, oss_fuzz_dir)


def run_cmd_harness_generation(args):
    """Entrypoint for command for harness generation."""

    # Prepare working directory.
    abs_workdir = os.path.abspath(args.workdir)

    # Run harness generation.
    projects_run = run_harness_generation(
        abs_workdir, args, args.project, args.function_name
    )

    # Log results.
    logger.info("Finished analysis")
    logger.info("Projects generated (%d): ", len(projects_run))


def run_full(args):
    """Generates builds and harnesses for repositories in input."""

    # Prepare working directory.
    workdir = setup_workdirs(args.workdir)

    abs_workdir = os.path.abspath(workdir)
    if not args.out:
        out_folder = get_next_out_folder()
    else:
        out_folder = args.out

    _run_build_generation(abs_workdir, out_folder, args)

    # Prepare fuzz introspector database.
    prepare_fuzz_introspector_db(out_folder, abs_workdir, args.build_jobs)

    # Run harness generation.
    projects_run = run_harness_generation(abs_workdir, args)

    # Log results.
    logger.info("Finished analysis")
    logger.info("Projects generated (%d): ", len(projects_run))


def _add_base_build_gen_arguments(parser):
    """Adds base arguments for build generation."""
    parser.add_argument(
        "--build-generation-mode",
        "-bgm",
        default="agent",
        help="Build generation mode. Defines how the build "
        "generation is done. "
        "Available modes: agent, template-based.",
    )
    parser.add_argument(
        "--input",
        "-i",
        help=(
            "Input to analyze. This can be either a URL to a git repository "
            "or a file with each line being a URL to a git reopsitory."
        ),
    )
    parser.add_argument(
        "--model",
        "-m",
        help=("Models available: " f'{", ".join(models.LLM.all_llm_names())}.'),
        type=str,
    )
    parser.add_argument(
        "--build-jobs",
        help="Parallel build-generator jobs to run.",
        default=2,
        type=int,
    )
    parser.add_argument(
        "--build-timeout",
        help="Timeout for build generation per project, in seconds.",
        default=0,
        type=int,
    )
    parser.add_argument("-w", "--workdir", help="Work directory to use")


def _add_base_harness_gen_arguments(parser):
    """Adds base arguments for harness generation."""
    parser.add_argument(
        "--hg-agent", "-ha", help="Enable agent harness generation", action="store_true"
    )
    parser.add_argument(
        "-gm",
        "--generate-benchmarks-max",
        help="Max targets to generate per benchmark heuristic.",
        type=int,
        default=5,
    )
    parser.add_argument(
        "-mr", "--max-round", type=int, default=5, help="Max trial round for agents."
    )
    parser.add_argument(
        "--benchmark-oracles",
        default=(
            "far-reach-low-coverage,low-cov-with-fuzz-keyword,"
            "easy-params-far-reach,test-migration"
        ),
    )


def parse_commandline():
    """Parse the commandline."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Parser for fixing OSS-Fuzz build
    fix_build_parser = subparsers.add_parser(
        "fix-build", help="Fixes OSS-Fuzz build scripts"
    )

    fix_build_parser.add_argument("--project", type=str, help="The project to fix")
    fix_build_parser.add_argument("--model", help="The model to use for build fixing.")
    fix_build_parser.add_argument(
        "-mr", "--max-round", type=int, default=20, help="Max trial round for agents."
    )

    # Run build generation.
    run_build_gen = subparsers.add_parser(
        "generate-builds",
        help="Generate OSS-Fuzz projects with build scripts but empty fuzzers.",
    )
    run_build_gen.add_argument(
        "--out", "-o", help="Directory to store output.", default="oss-fuzz-generated"
    )
    run_build_gen.add_argument(
        "-mr", "--max-round", type=int, default=5, help="Max trial round for agents."
    )
    _add_base_build_gen_arguments(run_build_gen)

    # Generate fuzz introspector database.
    run_generate_fi_db_parser = subparsers.add_parser(
        "generate-fuzz-introspector-database",
        help="Generates a fuzz introspector database from auto build projects.",
    )

    run_generate_fi_db_parser.add_argument("--generated-builds", required=True)
    run_generate_fi_db_parser.add_argument("--workdir", required=True)
    run_generate_fi_db_parser.add_argument("--parallel-build-jobs", type=int, default=5)

    # Run harness generation
    run_harness_generation_parser = subparsers.add_parser(
        "generate-harnesses",
        help="Harness generation of OSS-Fuzz projects.",
    )

    run_harness_generation_parser.add_argument(
        "--model",
        "-m",
        help=("Models available: " f'{", ".join(models.LLM.all_llm_names())}.'),
        type=str,
    )
    run_harness_generation_parser.add_argument(
        "-w", "--workdir", help="Work directory to use"
    )
    run_harness_generation_parser.add_argument(
        "--project", default="", help="Limit analysis to specified project."
    )
    run_harness_generation_parser.add_argument(
        "--function-name", default="", help="Target function"
    )
    _add_base_harness_gen_arguments(run_harness_generation_parser)

    # Run a full end to end generation.
    run_full_parser = subparsers.add_parser(
        "generate-full",
        help="Generate OSS-Fuzz integration from git URLs.",
    )
    run_full_parser.add_argument(
        "--out", "-o", help="Directory to store output.", default="oss-fuzz-generated"
    )

    _add_base_build_gen_arguments(run_full_parser)
    _add_base_harness_gen_arguments(run_full_parser)

    return parser.parse_args()


def main():
    args = parse_commandline()
    setup_logging()

    if args.command == "generate-full":
        run_full(args)
    if args.command == "generate-fuzz-introspector-database":
        run_fuzz_introspector_db_creation(
            args.workdir, args.generated_builds, args.parallel_build_jobs
        )
    if args.command == "generate-builds":
        run_build_generation(args)
    if args.command == "generate-harnesses":
        run_cmd_harness_generation(args)
    if args.command == "fix-build":
        run_cmd_fix_build(args)


if __name__ == "__main__":
    main()
