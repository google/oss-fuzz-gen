#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
This module provides functionality to generate experiment reports,
upload them to Google Cloud Storage (GCS), and generate/upload training data.
"""
import argparse
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional


class ReportUploader:
  """
  A class to generate reports, upload results and training data to GCS,
  and continuously monitor and update the reports during an experiment.
  """

  def __init__(self, results_dir: str, gcs_dir: str, benchmark_set: str,
               model: str):
    """
    Initialize the ReportUploader.
    """
    self.results_dir = Path(results_dir)
    self.gcs_dir = gcs_dir
    self.benchmark_set = benchmark_set
    self.model = model
    self.results_report_dir = Path('results-report')
    self.bucket_base_path = 'gs://oss-fuzz-gcb-experiment-run-logs/' \
                            'Result-reports'

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    self.logger = logging.getLogger(__name__)

  def _run_command(self, command: list) -> bool:
    """
    Run a subprocess command.
    """
    try:
      subprocess.run(command, check=True, capture_output=True, text=True)
      return True
    except subprocess.CalledProcessError as e:
      self.logger.error('Command failed: %s', ' '.join(command))
      self.logger.error('Error: %s', e.stderr)
      return False

  def _generate_report(self) -> bool:
    """
    Generate the experiment report.
    """
    self.logger.info('Generating report...')
    command = [
        'python', '-m', 'report.web', '-r',
        str(self.results_dir), '-b', self.benchmark_set, '-m', self.model, '-o',
        str(self.results_report_dir)
    ]
    return self._run_command(command)

  def upload_files(self,
                   source_path: str,
                   destination_path: str,
                   content_type: Optional[str] = None) -> bool:
    """
    Upload files or directories to GCS with an optional content type.
    """
    command = ['gsutil', '-q', '-m']
    if content_type:
      command.extend([
          '-h', f'Content-Type:{content_type}', '-h',
          'Cache-Control:public, max-age=3600'
      ])
    command.extend(['cp', '-r', source_path, destination_path])
    return self._run_command(command)

  def upload_report(self) -> bool:
    """
    Upload the generated report and related JSON and raw result files
    to GCS.
    """
    self.logger.info('Uploading report...')
    bucket_path = f'{self.bucket_base_path}/{self.gcs_dir}'

    # Upload HTML files.
    if not self.upload_files(f'{self.results_report_dir}/.', bucket_path,
                             'text/html'):
      return False

    # Upload JSON files.
    for json_file in self.results_report_dir.glob('**/*.json'):
      relative_path = json_file.relative_to(self.results_report_dir)
      if not self.upload_files(str(json_file), f'{bucket_path}/{relative_path}',
                               'application/json'):
        return False

    # Upload raw results.
    if not self.upload_files(str(self.results_dir), bucket_path):
      return False

    self.logger.info(
        'See the published report at https://llm-exp.oss-fuzz.com/'
        'Result-reports/%s/', self.gcs_dir)

    return True

  def _generate_training_data(self) -> bool:
    """
    Generate and upload training data.
    """
    self.logger.info('Generating and uploading training data...')

    # Remove existing training data.
    if Path('training_data').exists():
      subprocess.run(['rm', '-rf', 'training_data'], check=True)

    # Remove existing GCS training data.
    subprocess.run([
        'gsutil', '-q', 'rm', '-r',
        f'{self.bucket_base_path}/{self.gcs_dir}/training_data'
    ],
                   stderr=subprocess.DEVNULL,
                   check=True)

    configurations = [[], ['--group'], ['--coverage'],
                      ['--coverage', '--group']]

    for config in configurations:
      command = [
          'python', '-m', 'data_prep.parse_training_data', '--experiment-dir',
          str(self.results_dir), '--save-dir', 'training_data'
      ] + config

      if not self._run_command(command):
        return False

    # Upload training data.
    return self.upload_files(
        'training_data',
        f'{self.bucket_base_path}/{self.gcs_dir}/training_data')

  def update_report(self) -> bool:
    """
    Generate the report, upload it, and generate training data.
    """
    if not self._generate_report():
      return False

    if not self.upload_report():
      return False

    if not self._generate_training_data():
      return False

    return True

  def monitor_and_update(self):
    """
    Monitor experiment status and update report periodically.
    """
    # Sleep 5 minutes for the experiment to start.
    time.sleep(300)

    while not Path('/experiment_ended').exists():
      self.logger.info('Experiment is running... Updating report')
      self.update_report()
      time.sleep(600)

    self.logger.info('Experiment finished. Uploading final report...')
    self.update_report()
    self.logger.info('Final report uploaded.')


def parse_args() -> argparse.Namespace:
  """
  Parse command-line arguments.
  """
  parser = argparse.ArgumentParser(
      description='Upload experiment reports to GCS')
  parser.add_argument('results_dir',
                      help='Local directory with experiment results')
  parser.add_argument('gcs_dir', help='GCS directory for the report')
  parser.add_argument('benchmark_set', help='Benchmark set being used')
  parser.add_argument('model', help='LLM model used')
  return parser.parse_args()


def main():
  """
  Main function to initiate report uploading.
  """
  args = parse_args()
  os.makedirs('results-report', exist_ok=True)

  uploader = ReportUploader(args.results_dir, args.gcs_dir, args.benchmark_set,
                            args.model)
  uploader.monitor_and_update()


if __name__ == '__main__':
  main()
