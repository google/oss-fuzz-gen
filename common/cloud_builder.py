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
"""CloudBuilder executes agents in Cloud Builds."""
import argparse
import logging
import os
import re
import subprocess
import tempfile
import time
import uuid
from typing import Any

import google.api_core.client_options
import googleapiclient.errors
from google.api_core.exceptions import NotFound
from google.auth import default
from google.auth.transport.requests import Request
from google.cloud import storage
from googleapiclient.discovery import build as cloud_build

import utils
from agent.base_agent import BaseAgent
from results import Result

OF_REPO = 'https://github.com/google/oss-fuzz.git'
OFG_ROOT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
REGION = os.getenv('CLOUD_BUILD_LOCATION', 'us-west2')
REGIONAL_CLIENT_OPTIONS = google.api_core.client_options.ClientOptions(
    api_endpoint=f'https://{REGION}-cloudbuild.googleapis.com/')
_CHAT_HISTORY_PREFIX_PATTERN = r'^Step\s+#(\d+)\s+-\s+"agent-step":\s+'
_CHAT_HISTORY_START_MARKER = '<CHAT PROMPT:ROUND 01>'


class CloudBuilder:
  """A worker to execute llm-agents workflow in Google Cloud Build, providing a
  scalable and distributed alternative to local executions:
  - Request, monitor, and manage Google Cloud Build jobs.
  - Execute agent in the cloud environment, replicating the local conditions.
  - Transfer data and results between local and cloud environment.
  """

  def __init__(self, args: argparse.Namespace) -> None:
    self.tags = ['ofg', 'agent', args.cloud_experiment_name]
    self.exp_args = args
    self.credentials, self.project_id = default()
    assert self.project_id, 'Cloud experiment requires a Google cloud project.'
    assert hasattr(
        self.credentials,
        'refresh'), ('Cloud experiment requires a service account email')
    assert hasattr(self.credentials, 'service_account_email'), (
        'Cloud experiment requires a service account email')

    try:
      # TODO(dongge): Understand why this crashes in local experiments.
      self.credentials.refresh(Request())  # type: ignore
    except:
      pass
    self.bucket_name = args.cloud_experiment_bucket
    self.bucket = storage.Client().bucket(self.bucket_name)

    # pylint: disable=no-member
    self.builds = cloud_build(
        'cloudbuild',
        'v1',
        credentials=self.credentials,
        cache_discovery=False,
        client_options=REGIONAL_CLIENT_OPTIONS).projects().builds()
    self.storage_client = storage.Client(credentials=self.credentials)

  def _upload_to_gcs(self, local_file_path: str) -> str:
    """Uploads a file to Google Cloud Storage."""
    dest_file_name = os.path.basename(local_file_path)
    self.bucket.blob(dest_file_name).upload_from_filename(local_file_path)
    bucket_file_url = f'gs://{self.bucket_name}/{dest_file_name}'
    logging.info('Uploaded %s to %s', local_file_path, bucket_file_url)
    return bucket_file_url

  def _prepare_and_upload_archive(self, result_history: list[Result]) -> str:
    """Archives and uploads local OFG repo to cloud build."""
    dir_files = set(
        os.path.relpath(os.path.join(root, file))
        for root, _, files in os.walk(OFG_ROOT_DIR)
        for file in files)
    git_files = set(
        subprocess.check_output(['git', 'ls-files'],
                                cwd=OFG_ROOT_DIR,
                                text=True).splitlines())
    result_files = set(
        os.path.relpath(os.path.join(root, file))
        for root, _, files in os.walk(result_history[-1].work_dirs.base)
        for file in files)
    file_to_upload = list((dir_files & git_files) | result_files)

    with tempfile.TemporaryDirectory() as tmpdirname:
      archive_name = (f'{self.exp_args.cloud_experiment_name}-ofg-repo-'
                      f'{uuid.uuid4().hex}.tar.gz')
      archive_path = os.path.join(tmpdirname, archive_name)
      tar_command = ['tar', '-czf', archive_path] + file_to_upload
      subprocess.run(tar_command, cwd=OFG_ROOT_DIR, check=True)
      logging.info('Created archive: %s', archive_path)
      return self._upload_to_gcs(archive_path)

  def _request_cloud_build(self, ofg_repo_url: str, agent_dill_url: str,
                           results_dill_url: str,
                           new_result_filename: str) -> str:
    """Requests Cloud Build to execute the operation."""
    cloud_build_config = {
        'steps': [
            # Step 1: Download the dill files from GCS bucket.
            {
                'name': 'bash',
                'dir': '/workspace',
                'args': ['-c', 'mkdir -p dills']
            },
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'dir': '/workspace',
                'args': ['cp', agent_dill_url, 'dills/agent.pkl']
            },
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'dir': '/workspace',
                'args': ['cp', results_dill_url, 'dills/result_history.pkl']
            },
            # Step 2: Prepare OFG and OF repos.
            {
                'name':
                    'gcr.io/cloud-builders/gsutil',
                'entrypoint':
                    'bash',
                'args': [
                    '-c', f'gsutil cp {ofg_repo_url} /tmp/ofg-repo.tar.gz && '
                    'mkdir /workspace/ofg && '
                    f'tar -xzf /tmp/ofg-repo.tar.gz -C /workspace/ofg'
                ]
            },
            # Step 3: Prepare agent base image.
            {
                'name': 'gcr.io/cloud-builders/docker',
                'args': [
                    'build', '.', '-t',
                    ('us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/'
                     'agent-image'), '-f', 'Dockerfile.cloudbuild-agent'
                ],
                'dir': '/workspace/ofg/',
            },
            # Step 4: Prepare OSS-Fuzz repo.
            {
                'name':
                    'gcr.io/cloud-builders/docker',
                'dir':
                    '/workspace/ofg/',
                'args': [
                    'run', '--rm', '-v', '/workspace/ofg:/workspace/ofg',
                    ('us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/'
                     'agent-image'), 'python3.11', '-c',
                    'import os; from experiment import oss_fuzz_checkout; '
                    'oss_fuzz_checkout.clone_oss_fuzz("oss-fuzz"); '
                    'oss_fuzz_checkout.postprocess_oss_fuzz(); '
                ],
            },
            # Step 5: Run the Python script with the dill files.
            {
                'id':
                    'agent-step',
                'name':
                    'gcr.io/cloud-builders/docker',
                'args': [
                    'run',
                    '--rm',
                    '-v',
                    '/workspace:/workspace',
                    '-v',
                    '/var/run/docker.sock:/var/run/docker.sock',
                    '-e',
                    'VERTEX_AI_LOCATIONS=' +
                    os.getenv("VERTEX_AI_LOCATIONS", ""),
                    '--network=cloudbuild',
                    # Built from this repo's `Dockerfile.cloudbuild-agent`.
                    ('us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/'
                     'agent-image'),
                    'python3.11',
                    '-m',
                    'agent.base_agent',
                    '--agent',
                    '/workspace/dills/agent.pkl',
                    '--result-history',
                    '/workspace/dills/result_history.pkl',
                    '--result-new',
                    '/workspace/dills/new_result.pkl'
                ],
            },
            # Step 4: Upload the result to GCS bucket
            {
                'name': 'bash',
                'dir': '/workspace',
                'args': ['ls', '/workspace/dills/']
            },
            {
                'name':
                    'gcr.io/cloud-builders/gsutil',
                'dir':
                    '/workspace',
                'args': [
                    'cp', '/workspace/dills/new_result.pkl',
                    f'gs://{self.bucket_name}/{new_result_filename}'
                ]
            }
        ],
        'tags': self.tags,
        'timeout': '10800s',  # 3 hours
        'logsBucket': f'gs://{self.bucket_name}',
        'serviceAccount':
            f'projects/{self.project_id}/serviceAccounts/'
            f'{self.credentials.service_account_email}'  # type: ignore
    }
    pool_name = os.getenv('GCB_BUILDPOOL_NAME')
    if pool_name:
      cloud_build_config.setdefault('options', {})['pool'] = {'name': pool_name}
    logging.info(cloud_build_config)

    # Convert to YAML string and submit the Cloud Build request
    build_info = self.builds.create(projectId=self.project_id,
                                    body=cloud_build_config).execute()
    build_id = build_info.get('metadata', {}).get('build', {}).get('id', '')

    logging.info('Created Cloud Build ID %s at %s', build_id, REGION)
    return build_id

  def _wait_for_build(self, build_id: str) -> str:
    """Wait for a GCB build."""
    prev_status = status = None
    while status in [None, 'WORKING', 'QUEUED']:
      try:
        status = self.builds.get(projectId=self.project_id,
                                 id=build_id).execute().get('status')
        if status != prev_status:
          logging.info('Cloud Build %s Status: %s', build_id, status)
          prev_status = status
      except (googleapiclient.errors.HttpError, BrokenPipeError) as e:
        logging.warning('Failed to check cloud build status %s: %s', build_id,
                        e)
      time.sleep(60)  # Avoid rate limiting.
    return status or ''

  def _cancel_build(self, build_id: str) -> None:
    """Cancel a GCB build"""
    self.builds.cancel(projectId=self.project_id, id=build_id).execute()

  def _extract_chat_history(self, full_log: str) -> str:
    """Extracts the agent chat history from cloud build log."""
    in_chat = False
    chat_history = []
    for log_line in full_log.splitlines():
      if not re.match(_CHAT_HISTORY_PREFIX_PATTERN, log_line):
        continue
      if _CHAT_HISTORY_START_MARKER in log_line:
        in_chat = True
      if in_chat:
        stripped_line = re.sub(_CHAT_HISTORY_PREFIX_PATTERN, '', log_line)
        chat_history.append(stripped_line)
    return '\n'.join(chat_history)

  def _get_build_log(self, build_id: str) -> str:
    """Downloads the build log"""
    log_file_uri = f'log-{build_id}.txt'
    try:
      bucket = self.storage_client.bucket(self.bucket_name)
      blob = bucket.blob(log_file_uri)
      log_content = self._extract_chat_history(blob.download_as_text())
      logging.warning(log_content)
      return log_content
    except NotFound as e:
      logging.error('Cloud build log %s not found: %s', log_file_uri, e)
      return f'Cloud build log {log_file_uri} not found: {e}.'

  def _download_from_gcs(self, destination_file_name: str) -> None:
    """Downloads the result file from GCS."""
    source_blob_name = os.path.basename(destination_file_name)
    blob = self.bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)
    logging.info('Downloaded %s to %s', source_blob_name, destination_file_name)

  def run(self, agent: BaseAgent, result_history: list[Result],
          dill_dir: str) -> Any:
    """Runs agent on cloud build."""
    # Step 0: Add task-specific tags.
    # TODO(dongge): More tags, e.g., benchmark name.
    self.tags += [
        str(agent),
        str(result_history[-1].benchmark.project),
        str(result_history[-1].benchmark.function_name),
        str(result_history[-1].trial)
    ]
    # Step1: Generate dill files.
    agent_dill = utils.serialize_to_dill(
        agent, os.path.join(dill_dir, f'{uuid.uuid4().hex}.pkl'))
    results_dill = utils.serialize_to_dill(
        result_history, os.path.join(dill_dir, f'{uuid.uuid4().hex}.pkl'))
    # TODO(dongge): Encrypt dill files?

    # Step 2: Upload OFG repo and dill files to GCS.
    ofg_url = self._prepare_and_upload_archive(result_history)
    agent_url = self._upload_to_gcs(agent_dill)
    results_url = self._upload_to_gcs(results_dill)

    # Step 3: Request Cloud Build.
    new_result_filename = f'{uuid.uuid4().hex}.pkl'
    build_id = self._request_cloud_build(ofg_url, agent_url, results_url,
                                         new_result_filename)

    # Step 4: Download new result dill.
    cloud_build_log = ''
    new_result_dill = os.path.join(dill_dir, new_result_filename)
    try:
      cloud_build_final_status = self._wait_for_build(build_id)
      if cloud_build_final_status == 'SUCCESS':
        self._download_from_gcs(new_result_dill)
      else:
        logging.error('Cloud build %s failed with status: %s', build_id,
                      cloud_build_final_status)
        cloud_build_log += (f'Cloud build {build_id} failed with status: '
                            f'{cloud_build_final_status}.\n')
    except (KeyboardInterrupt, SystemExit) as e:
      self._cancel_build(build_id)
      logging.error('Cloud build %s cancled: %s', build_id, e)
      cloud_build_log += f'Cloud build {build_id} cancled: {e}.\n'

    cloud_build_log += self._get_build_log(build_id)

    # Step 4: Deserialize dilld file.
    result = utils.deserialize_from_dill(new_result_dill)
    if not result:
      cloud_build_log += f'Failed to deserialize from dill {new_result_dill}.\n'
      last_result = result_history[-1]
      result = Result(benchmark=last_result.benchmark,
                      trial=last_result.trial,
                      work_dirs=last_result.work_dirs,
                      author=agent)
    result.chat_history = {agent.name: cloud_build_log}

    return result
