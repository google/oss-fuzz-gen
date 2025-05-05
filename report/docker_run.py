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
Usage:
  docker_run.py [options]
"""

import argparse
import datetime
import logging
import os
import subprocess
import sys

# Configure logging to display all messages at or above INFO level
logging.basicConfig(level=logging.INFO)

BENCHMARK_SET = 'comparison'
FREQUENCY_LABEL = 'daily'
RUN_TIMEOUT = 300
SUB_DIR = 'default'
MODEL = 'vertex_ai_gemini-1-5'
DELAY = 0
NUM_SAMPLES = 10
LLM_FIX_LIMIT = 5
MAX_ROUND = 100
DATA_DIR = '/experiment/data-dir/'


def _parse_args(cmd) -> argparse.Namespace:
  """Parses the command line arguments."""
  parser = argparse.ArgumentParser(description='Run experiments')
  parser.add_argument(
      '-b',
      '--benchmark-set',
      type=str,
      default=BENCHMARK_SET,
      help=f'Experiment benchmark set, default: {BENCHMARK_SET}.')
  parser.add_argument(
      '-l',
      '--frequency-label',
      type=str,
      default=FREQUENCY_LABEL,
      help=
      f'Used as part of Cloud Build tags and GCS report directory, default: {FREQUENCY_LABEL}.'
  )
  parser.add_argument(
      '-to',
      '--run-timeout',
      type=int,
      default=RUN_TIMEOUT,
      help=f'Fuzzing timeout in seconds, default: {RUN_TIMEOUT} seconds.')
  parser.add_argument(
      '-sd',
      '--sub-dir',
      type=str,
      default=SUB_DIR,
      help=
      f'The subdirectory for the generated report in GCS, default: {SUB_DIR}.')
  parser.add_argument('-m',
                      '--model',
                      type=str,
                      default=MODEL,
                      help=f'Large Language Model name, default: {MODEL}.')
  parser.add_argument(
      '-d',
      '--delay',
      type=int,
      default=DELAY,
      help=f'Delay each benchmark experiment by N seconds, default: {DELAY}.')
  parser.add_argument(
      '-i',
      '--local-introspector',
      type=str,
      default="false",
      help=
      'If set to "true" will use a local version of fuzz introspector\'s webapp'
  )
  parser.add_argument(
      '-ns',
      '--num-samples',
      type=int,
      default=NUM_SAMPLES,
      help=f'The number of samples to request from LLM, default: {NUM_SAMPLES}')
  parser.add_argument(
      '-nf',
      '--llm-fix-limit',
      type=int,
      default=LLM_FIX_LIMIT,
      help=f'The number of fixes to request from LLM, default: {LLM_FIX_LIMIT}')
  parser.add_argument(
      '-vt',
      '--vary-temperature',
      type=str,
      default="true",
      help=
      'Use different temperatures for each sample. Set to "false" to disable.')
  parser.add_argument(
      '-ag',
      '--agent',
      type=str,
      default="false",
      help='Enables agent enhancement. Set to "true" to enable.')
  parser.add_argument('-mr',
                      '--max-round',
                      type=int,
                      default=MAX_ROUND,
                      help=f'Max trial round for agents, default: {MAX_ROUND}.')
  parser.add_argument(
      '-rd',
      '--redirect-outs',
      type=str,
      default="false",
      help=
      'Redirects experiments stdout/stderr to file. Set to "true" to enable.')

  args, additional_args = parser.parse_known_args(cmd)

  # Arguments after the first element ("--") separator.
  args.additional_args = additional_args[1:]

  # Parse boolean arguments
  args.local_introspector = args.local_introspector.lower() == "true"
  args.vary_temperature = args.vary_temperature.lower() == "true"
  args.agent = args.agent.lower() == "true"
  args.redirect_outs = args.redirect_outs.lower() == "true"

  return args


def _run_command(command: list[str], shell=False):
  """Runs a command and return its exit code."""
  process = subprocess.run(command, shell=shell)
  return process.returncode


def _authorize_gcloud():
  """Authorizes to gcloud"""
  # When running the docker container locally we need to activate the service
  # account from the env variable.
  # When running on GCP this step is unnecessary.
  google_creds = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', '')
  if google_creds:
    logging.info("GOOGLE APPLICATION CREDENTIALS set: %s.", google_creds)
    _run_command([
        'gcloud', 'auth', 'activate-service-account',
        'LLM-EVAL@oss-fuzz.iam.gserviceaccount.com', '--key-file', google_creds
    ])
  else:
    # TODO: Set GOOGLE_APPLICATION_CREDENTIALS and ensure cloud build uses it too.
    logging.info("GOOGLE APPLICATION CREDENTIALS is not set.")


def _log_common_args(args):
  """Prints args useful for logging"""
  logging.info("Benchmark set is %s.", args.benchmark_set)
  logging.info("Frequency label is %s.", args.frequency_label)
  logging.info("Run timeout is %s.", args.run_timeout)
  logging.info(
      "Sub-directory is %s. Please consider using sub-directory to classify your experiment.",
      args.sub_dir)
  logging.info("LLM is %s.", args.model)
  logging.info("DELAY is %s.", args.delay)


def main(cmd=None):
  """Main entrypoint"""
  if os.path.isfile('/experiment/data-dir.zip'):
    subprocess.check_call(
        'apt-get install -y zip && zip -s0 data-dir.zip --out newd.zip && unzip newd.zip && rm ./data-dir.z*',
        shell=True,
        cwd='/experiment')
  if os.path.isdir(DATA_DIR):
    run_on_data_from_scratch(cmd)
  else:
    run_standard(cmd)


def run_on_data_from_scratch(cmd=None):
  """Creates experiment for projects that are not in OSS-Fuzz upstream"""
  args = _parse_args(cmd)

  # Uses python3 by default and /venv/bin/python3 for Docker containers.
  python_path = "/venv/bin/python3" if os.path.exists(
      "/venv/bin/python3") else "python3"
  os.environ["PYTHON"] = python_path

  _authorize_gcloud()
  _log_common_args(args)

  # Launch starter, which set ups a Fuzz Introspector instance, which
  # will be used for creating benchmarks and extract context.
  logging.info('Running starter script')
  subprocess.check_call('/experiment/report/custom_oss_fuzz_fi_starter.sh',
                        shell=True)

  date = datetime.datetime.now().strftime('%Y-%m-%d')

  # Experiment name is used to label the Cloud Builds and as part of the
  # GCS directory that build logs are stored in.
  #
  # Example directory: 2023-12-02-daily-comparison
  experiment_name = f"{date}-{args.frequency_label}-{args.benchmark_set}"

  # Report directory uses the same name as experiment.
  # See upload_report.sh on how this is used.
  gcs_report_dir = f"{args.sub_dir}/{experiment_name}"

  # Trends report use a similarly named path.
  gcs_trend_report_path = f"{args.sub_dir}/{experiment_name}.json"

  local_results_dir = 'results'

  # Generate a report and upload it to GCS
  report_process = subprocess.Popen([
      "bash", "report/upload_report.sh", local_results_dir, gcs_report_dir,
      args.benchmark_set, args.model
  ])

  # Launch run_all_experiments.py
  # some notes:
  # - we will generate benchmarks using the local FI running
  # - we will use the oss-fuzz project of our workdir, which is
  #   the only one that has the projets.
  environ = os.environ.copy()

  # We need to make sure that we use our version of OSS-Fuzz
  environ['OSS_FUZZ_DATA_DIR'] = os.path.join(DATA_DIR, 'oss-fuzz2')

  # Get project names to analyse
  project_in_oss_fuzz = []
  for project_name in os.listdir(
      os.path.join(DATA_DIR, 'oss-fuzz2', 'build', 'out')):
    project_path = os.path.join(DATA_DIR, 'oss-fuzz2', 'build', 'out',
                                project_name)
    if not os.path.isdir(project_path):
      continue
    project_in_oss_fuzz.append(project_name)
  project_names = ','.join(project_in_oss_fuzz)

  introspector_endpoint = "http://127.0.0.1:8080/api"

  cmd = [python_path, 'run_all_experiments.py']
  cmd.append('-g')
  cmd.append(
      'far-reach-low-coverage,low-cov-with-fuzz-keyword,easy-params-far-reach')
  cmd.append('-gp')
  cmd.append(project_names)
  cmd.append('-gm')
  cmd.append(str(8))
  cmd.append('-e')
  cmd.append(introspector_endpoint)
  cmd.append('-mr')
  cmd.append(str(args.max_round))

  vary_temperature = [0.5, 0.6, 0.7, 0.8, 0.9] if args.vary_temperature else []
  cmd += [
      "--run-timeout",
      str(args.run_timeout), "--cloud-experiment-name", experiment_name,
      "--cloud-experiment-bucket", "oss-fuzz-gcb-experiment-run-logs",
      "--template-directory", "prompts/template_xml", "--work-dir",
      local_results_dir, "--num-samples",
      str(args.num_samples), "--delay",
      str(args.delay), "--context", "--temperature-list",
      *[str(temp) for temp in vary_temperature], "--model", args.model
  ]
  if args.agent:
    cmd.append("--agent")

  # Run the experiment and redirect to file if indicated.
  if args.redirect_outs:
    with open(f"{local_results_dir}/logs-from-run.txt", "w") as outfile:
      process = subprocess.run(cmd, stdout=outfile, stderr=outfile, env=environ)
      ret_val = process.returncode
  else:
    process = subprocess.run(cmd, env=environ)
    ret_val = process.returncode

  os.environ["ret_val"] = str(ret_val)

  with open("/experiment_ended", "w") as _f:
    pass

  logging.info("Shutting down introspector")
  try:
    subprocess.run(["curl", "--silent", "http://localhost:8080/api/shutdown"],
                   check=False,
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
  except Exception:
    pass

  # Wait for the report process to finish uploading.
  report_process.wait()

  trends_cmd = [
      python_path, "-m", "report.trends_report.upload_summary", "--results-dir",
      local_results_dir, "--output-path",
      f"gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/{gcs_trend_report_path}",
      "--name", experiment_name, "--date", date, "--url",
      f"https://llm-exp.oss-fuzz.com/Result-reports/{gcs_report_dir}",
      "--run-timeout",
      str(args.run_timeout), "--num-samples",
      str(args.num_samples), "--llm-fix-limit",
      str(args.llm_fix_limit), "--model", args.model, "--tags",
      args.frequency_label, args.sub_dir, "--commit-hash",
      subprocess.check_output(["git", "rev-parse",
                               "HEAD"]).decode().strip(), "--commit-date",
      subprocess.check_output(["git", "show", "--no-patch", "--format=%cs"
                              ]).decode().strip(), "--git-branch",
      subprocess.check_output(["git", "branch", "--show"]).decode().strip()
  ]

  subprocess.run(trends_cmd)

  # Exit with the return value of `./run_all_experiments`.
  return ret_val


def run_standard(cmd=None):
  """The main function."""
  args = _parse_args(cmd)

  # Uses python3 by default and /venv/bin/python3 for Docker containers.
  python_path = "/venv/bin/python3" if os.path.exists(
      "/venv/bin/python3") else "python3"
  os.environ["PYTHON"] = python_path

  _authorize_gcloud()
  _log_common_args(args)

  if args.local_introspector:
    os.environ["BENCHMARK_SET"] = args.benchmark_set
    introspector_endpoint = "http://127.0.0.1:8080/api"
    logging.info("LOCAL_INTROSPECTOR is enabled: %s", introspector_endpoint)
    _run_command(['bash', 'report/launch_local_introspector.sh'], shell=True)
  else:
    introspector_endpoint = "https://introspector.oss-fuzz.com/api"
    logging.info("LOCAL_INTROSPECTOR was not specified. Defaulting to %s.",
                 introspector_endpoint)

  logging.info("NUM_SAMPLES is %s.", args.num_samples)

  if args.llm_fix_limit:
    os.environ["LLM_FIX_LIMIT"] = str(args.llm_fix_limit)
    logging.info("LLM_FIX_LIMIT is set to %s.", args.llm_fix_limit)

  vary_temperature = [0.5, 0.6, 0.7, 0.8, 0.9] if args.vary_temperature else []

  date = datetime.datetime.now().strftime('%Y-%m-%d')
  local_results_dir = 'results'

  # Experiment name is used to label the Cloud Builds and as part of the
  # GCS directory that build logs are stored in.
  #
  # Example directory: 2023-12-02-daily-comparison
  experiment_name = f"{date}-{args.frequency_label}-{args.benchmark_set}"

  # Report directory uses the same name as experiment.
  # See upload_report.sh on how this is used.
  gcs_report_dir = f"{args.sub_dir}/{experiment_name}"

  # Trends report use a similarly named path.
  gcs_trend_report_path = f"{args.sub_dir}/{experiment_name}.json"

  # Generate a report and upload it to GCS
  report_process = subprocess.Popen([
      "bash", "report/upload_report.sh", local_results_dir, gcs_report_dir,
      args.benchmark_set, args.model
  ])

  # Prepare the command to run experiments
  run_cmd = [
      python_path, "run_all_experiments.py", "--benchmarks-directory",
      f"benchmark-sets/{args.benchmark_set}", "--run-timeout",
      str(args.run_timeout), "--cloud-experiment-name", experiment_name,
      "--cloud-experiment-bucket", "oss-fuzz-gcb-experiment-run-logs",
      "--template-directory", "prompts/template_xml", "--work-dir",
      local_results_dir, "--num-samples",
      str(args.num_samples), "--delay",
      str(args.delay), "--context", "--introspector-endpoint",
      introspector_endpoint, "--temperature-list",
      *[str(temp) for temp in vary_temperature], "--model", args.model,
      "--max-round",
      str(args.max_round)
  ]

  if args.agent:
    run_cmd.append("--agent")

  if args.additional_args:
    run_cmd.extend(args.additional_args)

  # Run the experiment and redirect to file if indicated.
  if args.redirect_outs:
    with open(f"{local_results_dir}/logs-from-run.txt", "w") as outfile:
      process = subprocess.run(run_cmd, stdout=outfile, stderr=outfile)
      ret_val = process.returncode
  else:
    process = subprocess.run(run_cmd)
    ret_val = process.returncode

  os.environ["ret_val"] = str(ret_val)

  with open("/experiment_ended", "w") as _f:
    pass

  if args.local_introspector:
    logging.info("Shutting down introspector")
    try:
      subprocess.run(["curl", "--silent", "http://localhost:8080/api/shutdown"],
                     check=False,
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    except Exception:
      pass

  # Wait for the report process to finish uploading.
  report_process.wait()

  trends_cmd = [
      python_path, "-m", "report.trends_report.upload_summary", "--results-dir",
      local_results_dir, "--output-path",
      f"gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/{gcs_trend_report_path}",
      "--name", experiment_name, "--date", date, "--url",
      f"https://llm-exp.oss-fuzz.com/Result-reports/{gcs_report_dir}",
      "--benchmark-set", args.benchmark_set, "--run-timeout",
      str(args.run_timeout), "--num-samples",
      str(args.num_samples), "--llm-fix-limit",
      str(args.llm_fix_limit), "--model", args.model, "--tags",
      args.frequency_label, args.sub_dir, "--commit-hash",
      subprocess.check_output(["git", "rev-parse",
                               "HEAD"]).decode().strip(), "--commit-date",
      subprocess.check_output(["git", "show", "--no-patch", "--format=%cs"
                              ]).decode().strip(), "--git-branch",
      subprocess.check_output(["git", "branch", "--show"]).decode().strip()
  ]

  subprocess.run(trends_cmd)

  # Exit with the return value of `./run_all_experiments`.
  return ret_val


if __name__ == "__main__":
  sys.exit(main())
