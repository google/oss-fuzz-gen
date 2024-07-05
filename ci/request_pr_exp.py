# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Requests an one-off GKE experiment with a PR ID.
Usage:
  python -m report.request_pr_exp -p <PR-ID> -n <YOUR-NAME>
e.g.,
  python -m report.request_pr_exp -p 73 -n dg
"""

import argparse
import logging
import os
import subprocess as sp
import sys
import time
from datetime import datetime
from string import Template

# Configure logging to display all messages at or above INFO level
logging.basicConfig(level=logging.INFO)

DEFAULT_CLUSTER = 'llm-experiment'
DEFAULT_LOCATION = 'us-central1-c'
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'k8s', 'pr-exp.yaml')
BENCHMARK_SET = 'comparison'
LLM_NAME = 'vertex_ai_gemini-1-5'
EXP_DELAY = 0
FUZZING_TIMEOUT = 300
REQUEST_CPU = 6
REQUEST_MEM = 30
NUM_SAMPLES = 2
NUM_FIXES = 2

PR_LINK_PREFIX = 'https://github.com/google/oss-fuzz-gen/pull'
JOB_LINK_PREFIX = ('https://console.cloud.google.com/kubernetes/job/'
                   '<LOCATION>/<CLUSTER>/default')
REPORT_LINK_PREFIX = 'https://llm-exp.oss-fuzz.com/Result-reports/ofg-pr'
# Use storage.cloud.google.com if we want to give external access.
BUCKET_LINK_PREFIX = ('https://console.cloud.google.com/storage/browser/'
                      'oss-fuzz-gcb-experiment-run-logs/Result-reports/ofg-pr')
BUCKET_GS_LINK_PREFIX = (
    'gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/ofg-pr')


def _parse_args(cmd) -> argparse.Namespace:
  """Parses the command line arguments."""
  parser = argparse.ArgumentParser(
      description=
      'Requests a GKE experiment with the given PR ID from OSS-Fuzz-Gen.')
  parser.add_argument(
      '-c',
      '--cluster',
      type=str,
      default=DEFAULT_CLUSTER,
      help=f'The cluster name to run GKE jobs, default: {DEFAULT_CLUSTER}')
  parser.add_argument(
      '-l',
      '--location',
      type=str,
      default=DEFAULT_LOCATION,
      help=f'The cluster location to run GKE jobs, default: {DEFAULT_LOCATION}')
  parser.add_argument(
      '-t',
      '--gke-template',
      type=str,
      default=TEMPLATE_PATH,
      help=f'The template to request GKE job, default: {TEMPLATE_PATH}')
  parser.add_argument(
      '-p',
      '--pr-id',
      type=int,
      required=True,
      help='The PR ID from OSS-Fuzz-Gen. Wait until the CI finishes building.')
  parser.add_argument(
      '-n',
      '--name-suffix',
      required=True,
      type=str,
      help=('Experiment name suffix (e.g., your name), this will be used in '
            'GKE job and result report.'))
  parser.add_argument(
      '-b',
      '--benchmark-set',
      type=str,
      default=BENCHMARK_SET,
      help=f'Experiment benchmark set, default: {BENCHMARK_SET}.')
  parser.add_argument('-m',
                      '--llm',
                      type=str,
                      default=LLM_NAME,
                      help=f'Large Language Model name, default: {LLM_NAME}.')
  parser.add_argument(
      '-d',
      '--delay',
      type=int,
      default=EXP_DELAY,
      help=('Delay each benchmark experiment by N seconds, default: '
            f'{EXP_DELAY}.'))
  parser.add_argument(
      '-f',
      '--force',
      action='store_true',
      help='Remove existing GKE job and bucket before creating new ones.')
  parser.add_argument(
      '-to',
      '--fuzzing-timeout',
      type=int,
      default=FUZZING_TIMEOUT,
      help=f'Fuzzing timeout in seconds, default: {FUZZING_TIMEOUT} seconds.')
  parser.add_argument(
      '-rc',
      '--request-cpus',
      type=int,
      default=REQUEST_CPU,
      help=f'CPU requested for experiment, default: {REQUEST_CPU}.')
  parser.add_argument(
      '-rm',
      '--request-memory',
      type=int,
      default=REQUEST_MEM,
      help=f'Memory requested for experiment in Gi, default: {REQUEST_MEM} Gi.')
  parser.add_argument(
      '-i',
      '--local-introspector',
      action='store_true',
      help='If set will use a local version of fuzz introspector\'s webapp')
  parser.add_argument(
      '-ns',
      '--num-samples',
      type=int,
      default=NUM_SAMPLES,
      help='The number of samples to request from LLM, default: {NUM_SAMPLES}')
  parser.add_argument(
      '-nf',
      '--num-fix',
      type=int,
      default=NUM_FIXES,
      help='The number of fixes to request from LLM, default: {NUM_FIXES}')
  args = parser.parse_args(cmd)

  assert os.path.isfile(
      args.gke_template), (f'GKE template does not exist: {args.gke_template}')

  # Construct experiment name and save it under args for simplicity.
  args.experiment_name = f'{args.pr_id}'
  if args.name_suffix:
    args.experiment_name = f'{args.experiment_name}-{args.name_suffix}'

  return args


def _remove_existing_job_bucket(gke_job_name: str, bucket_link: str,
                                bucket_gs_link: str):
  """Removes existing GKE job and gcloud bucket."""
  logging.info('Deleting GKE job: %s', gke_job_name)
  del_job = sp.run(['kubectl', 'delete', 'job', gke_job_name],
                   stdin=sp.DEVNULL,
                   stdout=sp.PIPE,
                   stderr=sp.PIPE,
                   check=False)
  if del_job.returncode:
    stdout = del_job.stdout.decode('utf-8')
    stderr = del_job.stderr.decode('utf-8')
    if 'Error from server (NotFound)' in stderr:
      logging.warning(stderr)
    else:
      logging.error('Failed to delete GKE job: %s.', gke_job_name)
      logging.error('STDOUT:\n  %s', stdout)
      logging.error('STDERR:\n  %s', stderr)
      sys.exit(1)

  # Wait for 5 seconds to ensure job is deleted and not writing to bucket.
  time.sleep(5)

  logging.info('Deleting gcloud bucket: %s', bucket_gs_link)
  del_bucket = sp.run(['gsutil', '-m', 'rm', '-r', bucket_gs_link],
                      stdin=sp.DEVNULL,
                      stdout=sp.PIPE,
                      stderr=sp.PIPE,
                      check=False)
  if del_bucket.returncode:
    logging.error('Failed to rm gcloud bucket directory:\n  %s', bucket_link)
    logging.error('STDOUT:\n  %s', del_bucket.stdout.decode('utf-8'))
    logging.error('STDERR:\n  %s', del_bucket.stderr.decode('utf-8'))


def _prepare_experiment_info(args: argparse.Namespace) -> tuple[str, str, str]:
  """
  Prepares and logs the key experiment information for easier accesses.
  """
  # GKE job name.
  gke_job_name = f'ofg-pr-{args.experiment_name}'

  # GKE job link.
  gke_job_link = f'{JOB_LINK_PREFIX}/ofg-pr-{args.experiment_name}'
  gke_job_link = gke_job_link.replace('<LOCATION>', args.location)
  gke_job_link = gke_job_link.replace('<CLUSTER>', args.cluster)

  # PR link.
  ofg_pr_link = f'{PR_LINK_PREFIX}/{args.pr_id}'

  # Report link.
  report_link = (
      f'{REPORT_LINK_PREFIX}/{datetime.now().strftime("%Y-%m-%d")}-'
      f'{args.pr_id}-{args.name_suffix}-{args.benchmark_set}/index.html')

  # Bucket links.
  bucket_link = (f'{BUCKET_LINK_PREFIX}/{datetime.now().strftime("%Y-%m-%d")}-'
                 f'{args.pr_id}-{args.name_suffix}-{args.benchmark_set}')
  bucket_gs_link = (
      f'{BUCKET_GS_LINK_PREFIX}/{datetime.now().strftime("%Y-%m-%d")}-'
      f'{args.pr_id}-{args.name_suffix}-{args.benchmark_set}')

  if args.force:
    logging.info(
        'FORCE mode enable, will first remove existing GKE job and bucket.')

  logging.info(
      'Requesting a GKE experiment named %s:\nPR: %s\nJOB: %s\nREPORT: %s\n'
      'BUCKET: %s\nBUCKET GS: `%s`\n',
      gke_job_name,
      ofg_pr_link,
      gke_job_link,
      report_link,
      bucket_link,
      bucket_gs_link,
  )
  return gke_job_name, bucket_link, bucket_gs_link


def _get_gke_credential(args: argparse.Namespace):
  """Authenticates gcloud account."""
  try:
    sp.run([
        'gcloud',
        'container',
        'clusters',
        'get-credentials',
        args.cluster,
        '--location',
        args.location,
    ],
           check=False)
  except Exception as e:
    logging.error('Failed to authenticate gcloud: %s', e)


def _fill_template(args: argparse.Namespace) -> str:
  """Fills the GKE template with |args| and returns the result YAML path."""
  exp_env_vars = os.environ.copy()
  exp_env_vars['PR_ID'] = str(args.pr_id)
  exp_env_vars['GKE_EXP_BENCHMARK'] = args.benchmark_set
  exp_env_vars['GKE_EXP_LLM'] = args.llm
  exp_env_vars['GKE_EXP_DELAY'] = args.delay
  exp_env_vars['GKE_EXP_FUZZING_TIMEOUT'] = str(args.fuzzing_timeout)
  exp_env_vars['GKE_EXP_NAME'] = args.experiment_name
  exp_env_vars['GKE_EXP_REQ_CPU'] = args.request_cpus
  exp_env_vars['GKE_EXP_REQ_MEM'] = f'{args.request_memory}Gi'
  if args.local_introspector:
    exp_env_vars['GKE_EXP_LOCAL_INTROSPECTOR'] = 'true'
  exp_env_vars['GKE_EXP_NUM_SAMPLES'] = f'{args.num_samples}'
  exp_env_vars['GKE_EXP_LLM_FIX_LIMIT'] = f'{args.llm_fix_limit}'

  with open(args.gke_template, 'r') as file:
    yaml_template = file.read()

  substituted_content = Template(yaml_template).safe_substitute(exp_env_vars)
  substituted_file_path = f'{os.path.splitext(args.gke_template)[0]}-sub.yaml'

  with open(substituted_file_path, 'w') as substituted_file:
    substituted_file.write(substituted_content)

  return substituted_file_path


def _request_experiment(substituted_file_path: str):
  """Requests an GKE experiment with |args| settings."""
  sp.run(['kubectl', 'create', '-f', substituted_file_path], check=True)


def main(cmd=None):
  """The main function."""
  args = _parse_args(cmd)
  gke_job_name, bucket_link, bucket_gs_link = _prepare_experiment_info(args)
  _get_gke_credential(args)
  if args.force:
    _remove_existing_job_bucket(gke_job_name, bucket_link, bucket_gs_link)
  _request_experiment(_fill_template(args))


if __name__ == "__main__":
  sys.exit(main())
