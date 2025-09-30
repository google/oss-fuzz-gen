"""A module to export a report to CSV or Google Sheets."""
import csv
import logging
import os
from abc import abstractmethod

from report.common import Results
from report.parse_logs import RunLogsParser

class BaseExporter:
  """Base class for exporters."""

  def __init__(self, results: Results, output_dir: str, base_url: str = ''):
    self._results = results
    self._output_dir = output_dir
    self._base_url = base_url.rstrip('/')
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

        project_name = benchmark_id.split("-")[1]

        for sample in samples:
          run_logs = self._results.get_run_logs(benchmark_id, sample.id) or ""
          parser = RunLogsParser(run_logs, benchmark_id, sample.id)
          crash_reproduction_path = parser.get_crash_reproduction_path()

          report_url = self._get_full_url(
              f"sample/{benchmark_id}/{sample.id}.html")
          reproducer_path = self._get_full_url(
              f'results/{benchmark_id}/artifacts/{sample.id}.fuzz_target-F0-01/'
              f'{crash_reproduction_path}') if crash_reproduction_path else ""

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
