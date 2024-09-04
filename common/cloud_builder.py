"""CloudBuilder executes agents in Cloud Builds."""
import argparse
import logging
import os
import pickle
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

from agent.base_agent import BaseAgent
from results import Result

OFG_REPO = 'https://github.com/google/oss-fuzz-gen.git'
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
    service_account_file = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', '')
    self.credentials = Credentials.from_service_account_file(
        service_account_file)
    self.builds = cloud_build('cloudbuild', 'v1',
                              credentials=self.credentials).projects().builds()

  def _serialize_to_pickle(self, variable: Any, path_prefix: str = '') -> str:
    """Serializes |variable| to a pickle file under |path_prefix| and returns
    the file path."""
    os.makedirs(path_prefix, exist_ok=True)
    filepath = os.path.join(path_prefix, f'{uuid.uuid4().hex}.pkl')
    with open(filepath, 'wb') as f:
      pickle.dump(variable, f)
    logging.info('Serialized %s to %s', variable, filepath)
    return filepath

  def _deserialize_from_pickle(self, pickle_path: Any) -> Result:
    """Serializes |variable| to a pickle file under |path_prefix| and returns
    the file path."""
    with open(pickle_path, 'rb') as f:
      obj = pickle.load(f)
    logging.info('Deserialized %s to %s', pickle_path, obj)
    return obj

  def _upload_to_gcs(self, local_file_path: str) -> str:
    """Uploads a file to Google Cloud Storage."""
    local_file_name = os.path.basename(local_file_path)
    bucket_file_url = f'gs://{self.bucket_name}/{local_file_name}'
    blob = self.bucket.blob(bucket_file_url)
    blob.upload_from_filename(local_file_path)
    logging.info('Uploaded %s to %s', local_file_name, bucket_file_url)
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
                           new_result_pickle_url: str) -> None:
    """Requests Cloud Build to execute the operation."""
    cloud_build_config = {
        'steps': [
            # Step 1: Download the pickle files from GCS bucket.
            {
                'name': 'gcr.io/cloud-builders/bash',
                'args': ['-c', 'mkdir -p /pickles']
            },
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'args': ['cp', agent_pickle_url, '/pickles/agent.pkl']
            },
            {
                'name':
                    'gcr.io/cloud-builders/gsutil',
                'args': [
                    'cp', results_pickle_url, '/pickles/result_history.pkl'
                ]
            },
            # Step 2: Prepare environment.
            {
                'name':
                    'gcr.io/cloud-builders/git',
                'entrypoint':
                    'bash',
                'args': [
                    '-c',
                    (f'git clone --no-checkout {OFG_REPO} /ofg && '
                     'cd /ofg && '
                     'git fetch --all && '
                     f'git checkout {self._get_current_commit_id()}')
                ]
            },
            {
                'name': 'python:3.9',
                'entrypoint': 'bash',
                'args': ['-c', 'cd /ofg && pip install -r requirements.txt']
            },
            # Step 3: Run the Python script with the pickle files
            {
                'name':
                    'python:3.9',
                'entrypoint':
                    'bash',
                'args': [
                    '-c', 'cp /pickles/agent.pkl /pickles/new_result.pkl'
                    # ('cd /ofg && python your_script.py /pickles/agent.pkl'
                    #  '/pickles/result_history.pkl')
                ]
            },
            # Step 4: Upload the result to GCS bucket
            {
                'name': 'gcr.io/cloud-builders/gsutil',
                'args': [
                    'cp', '/pickles/new_result.pkl', new_result_pickle_url
                ]
            }
        ],
        'timeout': '10800s',  # 3 hours
    }

    # Convert to YAML string and submit the Cloud Build request
    build_info = self.builds().create(projectId=self.project_id,
                                      body={
                                          'build': cloud_build_config
                                      }).execute()
    build_id = build_info.get('metadata', {}).get('build', {}).get('id', '')

    logging.info('Cloud Build ID: %s', build_id)
    return build_id

  def _wait_for_build(self, build_id):
    """Wait for a GCB build."""
    cloudbuild = cloud_build('cloudbuild',
                             'v1',
                             credentials=self.credentials,
                             cache_discovery=False,
                             client_options=US_CENTRAL_CLIENT_OPTIONS)

    while True:
      try:
        status = cloudbuild.projects().builds().get(projectId=self.project_id,
                                                    id=build_id).execute()
        if status.get('status') in ('SUCCESS', 'FAILURE', 'TIMEOUT',
                                    'INTERNAL_ERROR', 'EXPIRED', 'CANCELLED'):
          # Build done.
          return
      except (googleapiclient.errors.HttpError, BrokenPipeError):
        pass

      time.sleep(15)  # Avoid rate limiting.

  def _cancel_build(self, build_id):
    """Cancel a GCB build"""
    cloudbuild = cloud_build('cloudbuild',
                             'v1',
                             credentials=self.credentials,
                             cache_discovery=False,
                             client_options=US_CENTRAL_CLIENT_OPTIONS)
    cloudbuild.projects().builds().cancel(projectId=self.project_id,
                                          id=build_id).execute()

  def _download_result_file(self, source_blob_name: str,
                            destination_file_name: str) -> Any:
    """Downloads the result file from GCS."""

    blob = self.bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)
    logging.info('Downloaded %s to %s', source_blob_name, destination_file_name)

    with open('decrypted_generated_object.pkl', 'rb') as f:
      result_object = pickle.load(f)
    logging.info("Unpacked the result object from the pickle file.")
    return result_object

  def run(self, agent: BaseAgent, result_history: list[Result],
          pickle_dir: str) -> Any:
    """Runs agent on cloud build."""
    # Step1: Generate pickle files.
    agent_pickle = self._serialize_to_pickle(agent, pickle_dir)
    results_pickle = self._serialize_to_pickle(result_history, pickle_dir)
    # TODO(dongge): Encrypt pickle files?

    # Step 2: Upload pickle files to GCS.
    agent_url = self._upload_to_gcs(agent_pickle)
    results_url = self._upload_to_gcs(results_pickle)

    # Step 3: Request Cloud Build.
    new_result_filename = f'{uuid.uuid4().hex}.pkl'
    new_result_url = f'gs://{self.bucket_name}/{new_result_filename}'
    new_result_pickle = os.path.join(pickle_dir, new_result_filename)
    build_id = self._request_cloud_build(agent_url, results_url, new_result_url)
    try:
      self._wait_for_build(build_id)
      self._download_result_file(new_result_url, new_result_pickle)
    except (KeyboardInterrupt, SystemExit):
      self._cancel_build(build_id)

    # Step 4: Deserialize pickled file.
    return self._deserialize_from_pickle(new_result_pickle)
