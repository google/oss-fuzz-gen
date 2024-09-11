"""CloudBuilder executes agents in Cloud Builds."""
import argparse
import logging
import os
import subprocess
import tempfile
import time
import uuid
from typing import Any

import google.api_core.client_options
import googleapiclient.errors
from google.api_core.exceptions import NotFound
from google.auth import default
from google.cloud import storage
from googleapiclient.discovery import build as cloud_build

import utils
from agent.base_agent import BaseAgent
from results import BuildResult, Result

OF_REPO = 'https://github.com/google/oss-fuzz.git'
US_CENTRAL_CLIENT_OPTIONS = google.api_core.client_options.ClientOptions(
    api_endpoint='https://us-central1-cloudbuild.googleapis.com/')

AGENT_DOCKERFILE = """
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Python 3.11 and pip
RUN apt-get update && \
    apt-get install -y software-properties-common curl && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.11 python3.11-dev python3.11-venv \
        python3.11-distutils && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11

# Install Docker
RUN apt-get install -y ca-certificates gnupg lsb-release && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) \
        signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

ENV DEBIAN_FRONTEND=dialog

# Set the working directory
WORKDIR /workspace/ofg

# Copy the requirements file
COPY requirements.txt /workspace/ofg/

# Install Python dependencies
RUN pip3.11 install --ignore-installed -r /workspace/ofg/requirements.txt
"""


class CloudBuilder:
  """Encapsulate functions to request Google Cloud Builds to execute agents."""

  def __init__(self, args: argparse.Namespace) -> None:
    #TODO(dongge): extra tags.
    self.credentials, self.project_id = default()
    assert self.project_id, 'Cloud experiment requires a Google cloud project.'
    assert hasattr(self.credentials, 'service_account_email'), (
        'Cloud experiment requires a service account email')

    self.bucket_name = args.cloud_experiment_bucket
    self.bucket = storage.Client().bucket(self.bucket_name)

    self.builds = cloud_build(
        'cloudbuild',
        'v1',
        credentials=self.credentials,
        cache_discovery=False,
        client_options=US_CENTRAL_CLIENT_OPTIONS).projects().builds()
    self.storage_client = storage.Client(credentials=self.credentials)

  def _upload_to_gcs(self, local_file_path: str) -> str:
    """Uploads a file to Google Cloud Storage."""
    dest_file_name = os.path.basename(local_file_path)
    self.bucket.blob(dest_file_name).upload_from_filename(local_file_path)
    bucket_file_url = f'gs://{self.bucket_name}/{dest_file_name}'
    logging.info('Uploaded %s to %s', local_file_path, bucket_file_url)
    return bucket_file_url

  def _prepare_and_upload_archive(self) -> str:
    """Archives and uploads local OFG repo to cloud build."""
    ofg_repo = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'],
                                       text=True).strip()
    files_to_include = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        cwd=ofg_repo,
        text=True).splitlines()
    with tempfile.TemporaryDirectory() as tmpdirname:
      archive_name = f'ofg-repo-{uuid.uuid4().hex}.tar.gz'
      archive_path = os.path.join(tmpdirname, archive_name)
      tar_command = ['tar', '-cvzf', archive_path] + files_to_include
      subprocess.run(tar_command, cwd=ofg_repo, check=True)
      logging.info('Created archive: %s', archive_path)
      return self._upload_to_gcs(archive_path)

  def _request_cloud_build(self, ofg_repo_url: str, agent_pickle_url: str,
                           results_pickle_url: str,
                           new_result_filename: str) -> str:
    """Requests Cloud Build to execute the operation."""
    cloud_build_config = {
        'steps': [
            # Step 1: Download the pickle files from GCS bucket.
            {
                'name': 'bash',
                'dir': '/workspace',
                'args': ['-c', 'mkdir -p pickles']
            },
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'dir': '/workspace',
                'args': ['cp', agent_pickle_url, 'pickles/agent.pkl']
            },
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'dir': '/workspace',
                'args': [
                    'cp', results_pickle_url, 'pickles/result_history.pkl'
                ]
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
            {
                'name': 'gcr.io/cloud-builders/git',
                'dir': '/workspace',
                'args': ['clone', '--depth=1', OF_REPO, 'ofg/oss-fuzz']
            },
            {
                'name':
                    'gcr.io/cloud-builders/docker',
                'entrypoint':
                    'bash',
                'dir':
                    '/workspace/ofg',
                'args': [
                    '-c',
                    (f'echo "{AGENT_DOCKERFILE}" > Dockerfile && '
                     'docker build -t agent-image .')
                ]
            },
            # Step 3: Run the Python script with the pickle files
            {
                'id':
                    'agent-step',
                'name':
                    'gcr.io/cloud-builders/docker',
                'args': [
                    'run', '--rm', '-v', '/workspace:/workspace', '-v',
                    '/var/run/docker.sock:/var/run/docker.sock',
                    '--network=cloudbuild', 'agent-image', 'python3.11', '-m',
                    'agent.base_agent', '--agent',
                    '/workspace/pickles/agent.pkl', '--result-history',
                    '/workspace/pickles/result_history.pkl', '--result-new',
                    '/workspace/pickles/new_result.pkl'
                ],
            },
            # Step 4: Upload the result to GCS bucket
            {
                'name': 'bash',
                'dir': '/workspace',
                'args': ['ls', '/workspace/pickles/']
            },
            {
                'name':
                    'gcr.io/cloud-builders/gsutil',
                'dir':
                    '/workspace',
                'args': [
                    'cp', '/workspace/pickles/new_result.pkl',
                    f'gs://{self.bucket_name}/{new_result_filename}'
                ]
            }
        ],
        'timeout': '10800s',  # 3 hours
        'logsBucket': f'gs://{self.bucket_name}',
        'serviceAccount':
            f'projects/{self.project_id}/serviceAccounts/'
            f'{self.credentials.service_account_email}'  # type: ignore
    }

    # Convert to YAML string and submit the Cloud Build request
    build_info = self.builds.create(projectId=self.project_id,
                                    body=cloud_build_config).execute()
    build_id = build_info.get('metadata', {}).get('build', {}).get('id', '')

    logging.info('Cloud Build ID: %s', build_id)
    return build_id

  def _build_succeeds(self, build_id: str) -> bool:
    """Wait for a GCB build."""
    while True:
      try:
        status = self.builds.get(projectId=self.project_id,
                                 id=build_id).execute().get('status')
        logging.info('Cloud Build %s Status: %s', build_id, status)
        if status in ['WORKING', 'QUEUED']:
          time.sleep(60)  # Avoid rate limiting.
          continue
        return status == 'SUCCESS'
      except (googleapiclient.errors.HttpError, BrokenPipeError):
        return False

  def _cancel_build(self, build_id: str) -> None:
    """Cancel a GCB build"""
    self.builds.cancel(projectId=self.project_id, id=build_id).execute()

  def _get_build_log(self, build_id: str) -> str:
    """Downloads the build log"""
    log_file_uri = f'log-{build_id}.txt'
    try:
      bucket = self.storage_client.bucket(self.bucket_name)
      blob = bucket.blob(log_file_uri)
      log_content = blob.download_as_text()
      logging.debug(log_content)
      return log_content
    except NotFound as e:
      logging.error('Cloud build log %s not found: %s', log_file_uri, e)
      return ''

  def _download_from_gcs(self, destination_file_name: str) -> None:
    """Downloads the result file from GCS."""
    source_blob_name = os.path.basename(destination_file_name)
    blob = self.bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)
    logging.info('Downloaded %s to %s', source_blob_name, destination_file_name)

  def run(self, agent: BaseAgent, result_history: list[Result],
          pickle_dir: str) -> Any:
    """Runs agent on cloud build."""
    # Step1: Generate pickle files.
    agent_pickle = utils.serialize_to_pickle(
        agent, os.path.join(pickle_dir, f'{uuid.uuid4().hex}.pkl'))
    results_pickle = utils.serialize_to_pickle(
        result_history, os.path.join(pickle_dir, f'{uuid.uuid4().hex}.pkl'))
    # TODO(dongge): Encrypt pickle files?

    # Step 2: Upload OFG repo and pickle files to GCS.
    ofg_url = self._prepare_and_upload_archive()
    agent_url = self._upload_to_gcs(agent_pickle)
    results_url = self._upload_to_gcs(results_pickle)

    # Step 3: Request Cloud Build.
    new_result_filename = f'{uuid.uuid4().hex}.pkl'
    build_id = self._request_cloud_build(ofg_url, agent_url, results_url,
                                         new_result_filename)

    # Step 4: Download new result pickle.
    new_result_pickle = os.path.join(pickle_dir, new_result_filename)
    try:
      if self._build_succeeds(build_id):
        self._download_from_gcs(new_result_pickle)
    except (KeyboardInterrupt, SystemExit):
      self._cancel_build(build_id)
    build_log = self._get_build_log(build_id)

    # Step 4: Deserialize pickled file.
    result = utils.deserialize_from_pickle(new_result_pickle)
    if not result:
      last_result = result_history[-1]
      result = BuildResult(benchmark=last_result.benchmark,
                           trial=last_result.trial,
                           work_dirs=last_result.work_dirs,
                           author=agent)
    result.agent_dialogs = {agent.name: build_log}

    return result
