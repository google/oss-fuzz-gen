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
"""A module to export a report to CSV or Google Sheets."""
import csv
import logging
import os
from abc import abstractmethod

from report.common import Results
from report.parse_logs import RunLogsParser


class BaseExporter:
  """Base class for exporters."""

  def __init__(self,
               results: Results,
               output_dir: str,
               base_url: str = '',
               gcs_dir: str = ''):
    self._results = results
    self._output_dir = output_dir
    self._base_url = base_url.rstrip('/')
    self._gcs_dir = gcs_dir
    self._headers = [
        "Project", "Function Signature", "Sample", "Crash Type", "Compiles",
        "Crashes", "Coverage", "Line Coverage Diff", "Reproducer Path"
    ]

  @abstractmethod
  def generate(self) -> str:
    """Generate a report."""

  def _get_full_url(self, relative_path: str) -> str:
    """Convert relative path to full URL."""
    if not self._base_url:
      return relative_path
    return f"{self._base_url}/{relative_path}"

  def get_url_path(self) -> str:
    """Get the URL path to the CSV file."""
    return os.path.join(self._output_dir, 'crashes.csv')


class CSVExporter(BaseExporter):
  """Export a report to CSV."""

  def _get_reproducer_url(self, benchmark_id: str,
                          crash_reproduction_path: str) -> str:
    """Get the reproducer URL, using GCS bucket URL for cloud builds."""
    if not crash_reproduction_path:
      return ""

    if self._gcs_dir:
      return (f"https://console.cloud.google.com/storage/browser/"
              f"oss-fuzz-gcb-experiment-run-logs/Result-reports/"
              f"{self._gcs_dir}/results/{benchmark_id}/artifacts/"
              f"{crash_reproduction_path}")
    return self._get_full_url(
        f'results/{benchmark_id}/artifacts/{crash_reproduction_path}')

  def generate(self):
    """Generate a CSV file with the results."""
    csv_path = os.path.join(self._output_dir, 'crashes.csv')
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    with open(csv_path, 'w', newline='') as csvfile:
      writer = csv.DictWriter(csvfile, fieldnames=self._headers)
      writer.writeheader()

      benchmarks = []
      for benchmark_id in self._results.list_benchmark_ids():
        results, targets = self._results.get_results(benchmark_id)
        benchmark = self._results.match_benchmark(benchmark_id, results,
                                                  targets)
        benchmarks.append(benchmark)
        samples = self._results.get_samples(results, targets)

        project_name = benchmark_id.split("-")[1]

        for sample in samples:
          run_logs = self._results.get_run_logs(benchmark_id, sample.id) or ""
          parser = RunLogsParser(run_logs, benchmark_id, sample.id)
          crash_reproduction_path = parser.get_crash_reproduction_path()

          report_url = self._get_full_url(
              f"sample/{benchmark_id}/{sample.id}.html")
          reproducer_path = self._get_reproducer_url(benchmark_id,
                                                     crash_reproduction_path)

          writer.writerow({
              "Project":
                  project_name,
              "Function Signature":
                  benchmark.function,
              "Sample":
                  report_url,
              "Crashes":
                  sample.result.crashes,
              "Crash Type":
                  'False Positive'
                  if sample.result.is_semantic_error else 'True Positive',
              "Compiles":
                  sample.result.compiles,
              "Coverage":
                  sample.result.coverage,
              "Line Coverage Diff":
                  sample.result.line_coverage_diff,
              "Reproducer Path":
                  reproducer_path
          })

    logging.info("Created CSV file at %s", csv_path)
    return csv_path
