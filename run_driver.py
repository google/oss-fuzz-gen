import os
import argparse
import shutil
import logging
from multiprocessing import Pool
import subprocess as sp
from pathlib import Path

from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from experiment import oss_fuzz_checkout
from experiment.evaluator import Evaluator
import experiment.builder_runner as builder_runner_lib

"""Build and run a fuzzing trial for a given approach. Runtime length and number of trials can be provided as arguments"""

logger = logging.getLogger(__name__)
RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
BUILDER_RUNNER_TAG = "ghcr.io/gabe-sherman/oss-fuzz-base-runner:latest"


APPROACHES = ["bluebird_ofg", "ofg", "bluebird_promefuzz", "promefuzz", "ogharn"]
NUM_TRIALS = 1
RUN_TIMEOUT = 30
POOL_SIZE = 100

# Turn off caching to accomodate for specific dockerfile setups (i.e., sqlite since it has no git commits)
# We can enable caching for harness gen since this is not the actual fuzzing eval part.
oss_fuzz_checkout.ENABLE_CACHING = False
LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')

def parse_args():
    global NUM_TRIALS, APPROACHES, RUN_TIMEOUT, POOL_SIZE
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--project", type=str, required=True)
    parser.add_argument("-a", "--approach", type=str, choices=APPROACHES, nargs="+")
    parser.add_argument("-ft", "--fuzz-timeout", type=int)
    parser.add_argument("-nt", "--num-trials", type=int)
    parser.add_argument("-ps", "--pool-size", type=int)
    parser.add_argument("-r", "--results-dir", type=str, default = None)
    parser.add_argument('-c',
                      '--cloud-experiment-name',
                      type=str,
                      default='',
                      help='The name of the cloud experiment.')
    parser.add_argument('-cb',
                        '--cloud-experiment-bucket',
                        type=str,
                        help='A gcloud bucket to store experiment files.')
    
    args = parser.parse_args()

    if args.approach:
        APPROACHES = args.approach

    if args.num_trials:
        NUM_TRIALS = args.num_trials

    if args.fuzz_timeout:
        RUN_TIMEOUT = args.fuzz_timeout

    if args.pool_size:
        POOL_SIZE = args.pool_size

    return args

def check_custom_runner() -> None:
    inspect_cmd = ["docker", "image", "inspect", BUILDER_RUNNER_TAG]
    logger.debug("Checking for existing image: %s", " ".join(inspect_cmd))
    try:
        result = sp.run(
            inspect_cmd,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except sp.TimeoutExpired:
        logger.exception("Timeout while running docker inspect for %s", BUILDER_RUNNER_TAG)
        return False

    if result.returncode == 0:
        logger.info("Docker image %s already exists locally.", BUILDER_RUNNER_TAG)
        return True
    logger.info("Failed to find custom oss fuzz runner image! Please do this before running.")
    return False

def setup_evaluator(args, benchmark, workdir, approach, trial):
    if args.cloud_experiment_name:
      builder_runner = builder_runner_lib.CloudBuilderRunner(
          benchmark=benchmark,
          work_dirs=workdir,
          run_timeout=RUN_TIMEOUT,
          experiment_name=f"fuzz_trial_{benchmark.project}_{approach}_trial{trial}_",
          experiment_bucket=args.cloud_experiment_bucket,
          use_afl_engine=True,
          approach=approach
      )
    else:
      builder_runner = builder_runner_lib.BuilderRunner(
          benchmark=benchmark,
          work_dirs=workdir,
          run_timeout=RUN_TIMEOUT,
          use_afl_engine=True,
          approach=approach
      )

    evaluator = Evaluator(builder_runner, benchmark, workdir)

    return evaluator

def clone_custom_oss(dest_path: str) -> bool:
    command = [
        "git",
        "clone",
        "https://github.com/FuturesLab/oss-fuzz-bluebird.git",
        dest_path
    ]

    result = sp.run(
        command,
        stdout=sp.PIPE,
        stderr=sp.PIPE,
        text=True,
        timeout=300,
        check=False,
    )

    if result.returncode != 0:
        logger.error("Git clone failed with return code %d", result.returncode)
        logger.error("STDOUT:\n%s", result.stdout)
        logger.error("STDERR:\n%s", result.stderr)
        return False

    return True

def setup_logger():
    logging.basicConfig(
      level="INFO",
      format=LOG_FMT,
      datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.getLogger('').setLevel("INFO")

def run_fuzz_trial(args: argparse.Namespace, workdir_base: str, appr: str, trial: int):
    """Spawn the fuzzing campaign with a specific trial and approach identifier"""
    try:
        source_dir = os.path.join(RUNNER_DIR, "fuzzing_trials", "target_src", args.project, appr)
        build_script_path = os.path.join(RUNNER_DIR, "fuzzing_trials", "target_src", args.project, "build.sh")
        test_name = f"{args.project}-{appr}-{trial}".lower()
        workdir = WorkDirs(os.path.join(workdir_base, f'output-{test_name}'))
        evaluator = setup_evaluator(args, benchmark, workdir, appr, trial)
        Evaluator.create_ossfuzz_project_batched_harness(benchmark, test_name, source_dir, build_script_path)
        evaluator.builder_runner.build_and_run(test_name, source_dir, 0, benchmark.language,
                cloud_build_tags=[
                        str(trial),
                        'Execution',
                        appr,
                        benchmark.project,
                    ]
                )
        return True
    except Exception as e:
        logger.error("Worker ERROR! Appr %s failed: %s", appr, e)
        return False
        
    
if __name__ == "__main__":
    args = parse_args()
    setup_logger()

    # Get the target benchmark yaml
    benchmarks = Benchmark.from_yaml(os.path.join(RUNNER_DIR, "targets", f"{args.project}.yaml"))
    benchmark = benchmarks[0]

    # Set up custom oss-fuzz repo
    oss_path = os.path.join(RUNNER_DIR, "oss-fuzz")
    if not os.path.exists(oss_path):
        clone_custom_oss(oss_path)
    oss_fuzz_checkout.OSS_FUZZ_DIR = oss_path
    oss_fuzz_checkout.postprocess_oss_fuzz()
    if not args.cloud_experiment_name:
        check_custom_runner()

    # Set up result path
    result_dir = args.results_dir if args.results_dir else f"results-{args.project}"
    workdir_base = os.path.join(RUNNER_DIR, result_dir)

    # Begin fuzzing trials
    experiment_tasks = []
    with Pool(POOL_SIZE, maxtasksperchild=1) as p:
        for trial in range(0, NUM_TRIALS):
            for appr in APPROACHES:
                fuzz_task = p.apply_async(run_fuzz_trial, (args, workdir_base, appr, trial))
                experiment_tasks.append(fuzz_task)

        experiment_results = [task.get() for task in experiment_tasks]
        p.close()
        p.join()