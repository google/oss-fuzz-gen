"""CloudBuilder executes agents in Cloud Builds."""
import argparse
import logging
import os
import subprocess
import time
import uuid
from typing import Any

import google.api_core.client_options
import googleapiclient.errors
from google.auth import default
from google.cloud import storage
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build as cloud_build

import utils
from agent.base_agent import BaseAgent
from results import Result

OFG_REPO = 'https://github.com/google/oss-fuzz-gen.git'
OF_REPO = 'https://github.com/google/oss-fuzz.git'
US_CENTRAL_CLIENT_OPTIONS = google.api_core.client_options.ClientOptions(
    api_endpoint='https://us-central1-cloudbuild.googleapis.com/')


class CloudBuilder:
  """Encapsulate functions to request Google Cloud Builds to execute agents."""

  def __init__(self, args: argparse.Namespace) -> None:
    #TODO(dongge): extra tags.
    _, self.project_id = default()
    assert self.project_id, 'Cloud experiment requires a Google cloud project.'

    self.bucket_name = args.cloud_experiment_bucket
    self.bucket = storage.Client().bucket(self.bucket_name)

    # Service account.
    self.service_account = os.getenv('GOOGLE_SERVICE_ACCOUNT', '')
    service_account_file = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', '')
    logging.info('service_account_file: %s', service_account_file)
    self.credentials = Credentials.from_service_account_file(
        service_account_file)
    self.builds = cloud_build(
        'cloudbuild',
        'v1',
        credentials=self.credentials,
        cache_discovery=False,
        client_options=US_CENTRAL_CLIENT_OPTIONS).projects().builds()

  def _upload_to_gcs(self, local_file_path: str) -> str:
    """Uploads a file to Google Cloud Storage."""
    dest_file_name = os.path.basename(local_file_path)
    self.bucket.blob(dest_file_name).upload_from_filename(local_file_path)
    bucket_file_url = f'gs://{self.bucket_name}/{dest_file_name}'
    logging.info('Uploaded %s to %s', local_file_path, bucket_file_url)
    return bucket_file_url

  def _get_current_commit_id(self) -> str:
    """Gets the current commit ID from the local git repository."""
    try:
      commit_id = subprocess.check_output(['git', 'rev-parse',
                                           'HEAD']).decode('utf-8').strip()
      return commit_id
    except subprocess.CalledProcessError as e:
      logging.error('Error fetching the current commit ID: %s', e)
      return ''

  def _request_cloud_build(self, agent_pickle_url: str, results_pickle_url: str,
                           new_result_filename: str) -> None:
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
            # Step 2: Prepare git repos.
            {
                'name':
                    'gcr.io/cloud-builders/git',
                'entrypoint':
                    'bash',
                'dir':
                    '/workspace',
                'args': [
                    '-c',
                    (f'git clone --no-checkout {OFG_REPO} ofg && cd ofg &&'
                     'git fetch --all && '
                     f'git checkout {self._get_current_commit_id()}')
                ]
            },
            {
                'name': 'gcr.io/cloud-builders/git',
                'entrypoint': 'bash',
                'dir': '/workspace',
                'args': ['-c', f'git clone --depth=1 {OF_REPO} ofg/oss-fuzz']
            },
            # Step 3: Run the Python script with the pickle files
            {
                'name':
                    'gcr.io/cloud-builders/docker',
                'entrypoint':
                    'bash',
                'dir':
                    '/workspace/ofg',
                'args': [
                    '-c',
                    """
                    # Install Python 3.11 and pip
                    apt-get update &&
                    apt-get install -y software-properties-common &&
                    add-apt-repository ppa:deadsnakes/ppa &&
                    apt-get update &&
                    apt-get install -y python3.11 python3.11-dev \
                        python3.11-venv python3.11-distutils &&
                    curl -sS https://bootstrap.pypa.io/get-pip.py | \
                        python3.11 &&

                    # Install Python dependencies
                    pip3.11 install --ignore-installed -r \
                        /workspace/ofg/requirements.txt &&

                    # Run agent
                    python3.11 -m agent.base_agent \
                        /workspace/pickles/agent.pkl \
                        /workspace/pickles/result_history.pkl \
                        /workspace/pickles/new_result.pkl
                    """,
                ]
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
        'timeout':
            '10800s',  # 3 hours
        'logsBucket':
            f'gs://{self.bucket_name}',
        'serviceAccount':
            f'projects/{self.project_id}/serviceAccounts/{self.service_account}'
    }

    # Convert to YAML string and submit the Cloud Build request
    build_info = self.builds.create(projectId=self.project_id,
                                    body=cloud_build_config).execute()
    build_id = build_info.get('metadata', {}).get('build', {}).get('id', '')

    logging.info('Cloud Build ID: %s', build_id)
    return build_id

  def _build_succeeds(self, build_id):
    """Wait for a GCB build."""
    while True:
      try:
        status = self.builds.get(projectId=self.project_id,
                                 id=build_id).execute().get('status')
        logging.info('Cloud Build %s Status: %s', build_id, status)
        if status in ['WORKING', 'QUEUED']:
          time.sleep(15)  # Avoid rate limiting.
          continue
        return status == 'SUCCESS'
      except (googleapiclient.errors.HttpError, BrokenPipeError):
        return False

  def _cancel_build(self, build_id):
    """Cancel a GCB build"""
    self.builds.cancel(projectId=self.project_id, id=build_id).execute()

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

    # Step 2: Upload pickle files to GCS.
    agent_url = self._upload_to_gcs(agent_pickle)
    results_url = self._upload_to_gcs(results_pickle)

    # Step 3: Request Cloud Build.
    new_result_filename = f'{uuid.uuid4().hex}.pkl'
    build_id = self._request_cloud_build(agent_url, results_url,
                                         new_result_filename)

    # Step 4: Download new result pickle.
    new_result_pickle = os.path.join(pickle_dir, new_result_filename)
    try:
      if self._build_succeeds(build_id):
        self._download_from_gcs(new_result_pickle)
    except (KeyboardInterrupt, SystemExit):
      self._cancel_build(build_id)

    # Step 4: Deserialize pickled file.
    return utils.deserialize_from_pickle(new_result_pickle)
