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

class BaseExporter:
  """Base class for exporters."""

  def __init__(self, results: Results, output_dir: str):
    self._results = results
    self._output_dir = output_dir

  @abstractmethod
  def generate(self):
    """Generate a report."""
    pass

class CSVExporter(BaseExporter):
  """Export a report to CSV."""

  def __init__(self, results: Results, output_dir: str):
    super().__init__(results, output_dir)

  def generate(self):
    """Generate a CSV file with the results."""
    csv_path = os.path.join(self._output_dir, 'crashes.csv')
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    with open(csv_path, 'w', newline='') as csvfile:
      fieldnames = ["Project", "Benchmark", "Sample", "Status", "Compiles", "Crashes"]

      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
      writer.writeheader()

      benchmarks = []
      for benchmark_id in self._results.list_benchmark_ids():
        results, targets = self._results.get_results(benchmark_id)
        benchmark = self._results.match_benchmark(benchmark_id, results,
                                                  targets)
        benchmarks.append(benchmark)
        samples = self._results.get_samples(results, targets)
        project = benchmark_id.split("-")[1]

        for sample in samples:
          writer.writerow({
              "Project": project,
              "Benchmark": benchmark_id,
              "Sample": sample.id,
              "Status": sample.status,
              "Compiles": sample.result.compiles,
              "Crashes": sample.result.crashes
          })

    logging.info("Created CSV file at %s", csv_path)
    return csv_path

  def get_url_path(self):
    """Get the URL path to the CSV file."""
    return os.path.join(self._output_dir, 'crashes.csv')


class GoogleSheetsExporter(BaseExporter):
  """Export a report to Google Sheets."""

  def __init__(self, results: Results, output_dir: str):
    super().__init__(results, output_dir)


#   def generate(self):
#     """Generate a Google Sheets report."""
#     pass
