# Copyright 2024 Google LLC
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
"""Common libraries for report generation."""

import dataclasses
import io
import json
import logging
import os
import re
from typing import List, Optional

import yaml
from google.cloud import storage

import run_one_experiment
from data_prep import project_src
from experiment import evaluator
from experiment.workdir import WorkDirs

MAX_RUN_LOGS_LEN = 16 * 1024

TARGET_EXTS = project_src.SEARCH_EXTS + ['.java', '.py']


@dataclasses.dataclass
class AccumulatedResult:
  """Container for storing accumulated results."""
  compiles: int = 0
  crashes: int = 0
  crash_cases: int = 0
  total_runs: int = 0
  total_coverage: float = 0.0
  total_line_coverage_diff: float = 0.0

  @property
  def average_coverage(self) -> float:
    return self.total_coverage / float(self.total_runs)

  @property
  def average_line_coverage_diff(self) -> float:
    return self.total_line_coverage_diff / float(self.total_runs)

  @property
  def build_rate(self) -> float:
    return float(self.compiles) / float(self.total_runs)


@dataclasses.dataclass
class Benchmark:
  """The class of a benchmark function and its experiment results."""
  id: str
  status: str
  result: run_one_experiment.AggregatedResult
  signature: str = ''
  project: str = ''
  function: str = ''


@dataclasses.dataclass
class Sample:
  """Result of a fuzz target sample of a benchmark."""
  id: str
  status: str
  result: evaluator.Result

  @property
  def stacktrace(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/stacktrace'

  @property
  def target_binary(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/target_binary'

  @property
  def reproducer(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return f'{reproducer_link}/artifacts'

  @property
  def run_log(self) -> str:
    if not self.result:
      return ''
    reproducer_link = self.result.reproducer_path
    return reproducer_link.removesuffix('reproducer') + 'run.log'


@dataclasses.dataclass
class Target:
  code: str
  fixer_prompt: Optional[str] = None


class FileSystem:
  """
  FileSystem provides a wrapper over standard library and GCS client and
  automatically chooses which to use based on the provided path.
  """

  _gcs_client = None

  @classmethod
  def _get_gcs_client(cls):
    """
    Returns a cached storage client (a new one is created on first call.

    A new client does authentication on first call, so caching the client will
    same multiple authentication round trips to GCP.
    """
    if cls._gcs_client is None:
      cls._gcs_client = storage.Client()

    return cls._gcs_client

  def __init__(self, path: str):
    logging.debug('file operation %s', path)
    self._path = path
    self._gcs_bucket: Optional[storage.Bucket] = None

    if path.startswith('gs://'):
      path = path.removeprefix('gs://')
      self._gcs_bucket = FileSystem._get_gcs_client().bucket(path.split('/')[0])
      self._path = '/'.join(path.split('/')[1:])

  def listdir(self) -> List[str]:
    """listdir returns a list of files and directories in path."""
    if self._gcs_bucket is not None:
      # Make sure the path ends with a /, otherwise GCS just returns the
      # directory as a prefix and not list the contents.
      prefix = self._path
      if not self._path.endswith('/'):
        prefix = f'{self._path}/'

      # Unfortunately GCS doesn't work like a normal file system and the client
      # library doesn't even pretend there is a directory hierarchy.
      # The list API does return a list of prefixes that we can join with the
      # list of objects to get something close to listdir(). But client library
      # is pretty weird and it stores the prefixes on the iterator...
      # https://github.com/googleapis/python-storage/blob/64edbd922a605247203790a90f9536d54e3a705a/google/cloud/storage/client.py#L1356
      it = self._gcs_bucket.list_blobs(prefix=prefix, delimiter='/')
      paths = [f.name for f in it] + [p.removesuffix('/') for p in it.prefixes]
      r = [p.removeprefix(prefix) for p in paths]
      return r

    return os.listdir(self._path)

  def exists(self) -> bool:
    """exists returns true if the path is a file or directory."""
    if self._gcs_bucket is not None:
      return self.isfile() or self.isdir()

    return os.path.exists(self._path)

  def isfile(self) -> bool:
    """isfile returns true if the path is a file."""
    if self._gcs_bucket is not None:
      return self._gcs_bucket.blob(self._path).exists()

    return os.path.isfile(self._path)

  def isdir(self) -> bool:
    """isfile returns true if the path is a directory."""
    if self._gcs_bucket is not None:
      return len(self.listdir()) > 0

    return os.path.isdir(self._path)

  def makedirs(self):
    """makedirs create parent(s) and directory in specified path."""
    if self._gcs_bucket is not None:
      # Do nothing. GCS doesn't have directories and files can be created with
      # any path.
      return

    os.makedirs(self._path)

  def open(self, *args, **kwargs) -> io.IOBase:
    """
    open returns a file handle to the file located at the specified path.

    It has identical function signature to standard library open().
    """
    if self._gcs_bucket is not None:
      return self._gcs_bucket.blob(self._path).open(*args, **kwargs)

    return open(self._path, *args, **kwargs)

  def getsize(self) -> int:
    """getsize returns the byte size of the file at the specified path."""
    if self._gcs_bucket is not None:
      blob = self._gcs_bucket.get_blob(self._path)
      if blob is None:
        raise FileNotFoundError(
            'GCS blob not found gs://{self._gcs_bucket.bucket}/{self._path}.')

      # size can be None if use Bucket.blob() instead of Bucket.get_blob(). The
      # type checker doesn't know this and insists we check if size is None.
      return blob.size if blob.size is not None else 0

    return os.path.getsize(self._path)


class Results:
  """Results provides functions to explore the experiment results in a particular directory."""

  def __init__(self, results_dir='results', benchmark_set='all'):
    self._results_dir = results_dir
    self._benchmark_dir = os.path.join('benchmark-sets', benchmark_set)

  def list_benchmark_ids(self) -> List[str]:
    return sorted(
        filter(self._is_valid_benchmark_dir,
               FileSystem(self._results_dir).listdir()))

  def match_benchmark(self, benchmark_id: str, results: list[evaluator.Result],
                      targets: list[str]) -> Benchmark:
    """Returns a benchmark class based on |benchmark_id|."""
    status = 'Done' if results and all(results) else 'Running'
    filtered_results = [(i, stat) for i, stat in enumerate(results) if stat]

    if filtered_results:
      result = run_one_experiment.aggregate_results(filtered_results, targets)
    else:
      result = run_one_experiment.AggregatedResult()

    return self._create_benchmark(benchmark_id, status, result)

  def get_final_target_code(self, benchmark: str, sample: str) -> str:
    """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
    targets_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')

    for name in sorted(FileSystem(targets_dir).listdir()):
      path = os.path.join(targets_dir, name)
      if name.startswith(sample + '.') and FileSystem(path).isfile():
        with FileSystem(path).open() as f:
          code = f.read()
          code = json.dumps(code)
        return code
    return ''

  def get_logs(self, benchmark: str, sample: str) -> str:
    status_dir = os.path.join(self._results_dir, benchmark, 'status')
    results_path = os.path.join(status_dir, sample, 'log.txt')
    if not FileSystem(results_path).exists():
      return ''

    with FileSystem(results_path).open() as f:
      return f.read()

  def get_run_logs(self, benchmark: str, sample: str) -> str:
    """Returns the content of the last run log."""
    run_logs_dir = os.path.join(self._results_dir, benchmark, 'logs', 'run')
    largest_iteration, last_log_file = -1, None
    for name in FileSystem(run_logs_dir).listdir():
      if name.startswith(sample + '.'):
        iteration = WorkDirs.get_run_log_iteration(name)
        if iteration is None:
          # Be compatible with older results where no '-Fxx' in run log file name
          last_log_file = name
          break

        if largest_iteration < iteration:
          largest_iteration, last_log_file = iteration, name

    if not last_log_file:
      return ''

    log_path = os.path.join(run_logs_dir, last_log_file)
    log_size = FileSystem(log_path).getsize()
    with FileSystem(log_path).open(errors='replace') as f:
      if log_size <= MAX_RUN_LOGS_LEN:
        return f.read()

      truncated_len = MAX_RUN_LOGS_LEN // 2
      logs_beginning = f.read(truncated_len)
      f.seek(log_size - truncated_len - 1, os.SEEK_SET)
      logs_ending = f.read()

      return logs_beginning + '\n...truncated...\n' + logs_ending

    return ''

  def get_triage(self, benchmark: str, sample: str) -> str:
    """Gets the triage of benchmark |benchmark| with sample ID |sample|."""
    fixed_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')
    triage_dir = os.path.join(fixed_dir, f'{sample}-triage')
    if not os.path.exists(triage_dir):
      return ''

    for name in os.listdir(triage_dir):
      if name.endswith('.txt') and name != 'prompt.txt':
        triage_path = os.path.join(triage_dir, name)
        with open(triage_path) as f:
          return f.read()

    return ''

  def get_targets(self, benchmark: str, sample: str) -> list[Target]:
    """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
    targets_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')
    targets = []

    for name in sorted(FileSystem(targets_dir).listdir()):
      path = os.path.join(targets_dir, name)
      if name.startswith(sample + '.') and FileSystem(path).isfile():
        logging.debug(path)
        with FileSystem(path).open() as f:
          code = f.read()
        targets.insert(0, Target(code=code))

      if name.startswith(sample + '-F') and FileSystem(path).isdir():
        targets.append(self._get_fixed_target(path))

    return targets

  def get_samples(self, results: list[evaluator.Result],
                  targets: list[str]) -> list[Sample]:
    """Gets the samples and their status of the given benchmark |bnmk|."""
    samples = []

    for i, sample_id in enumerate(self._sample_ids(targets)):
      status = 'Running'
      result = evaluator.Result()
      if results[i]:
        status = 'Done'
        result = results[i]

      samples.append(Sample(sample_id, status, result))

    return samples

  def get_prompt(self, benchmark: str) -> Optional[str]:
    root_dir = os.path.join(self._results_dir, benchmark)
    for name in FileSystem(root_dir).listdir():
      if re.match(r'^prompt.*txt$', name):
        with FileSystem(os.path.join(root_dir, name)).open() as f:
          content = f.read()

        # Prepare prompt text for HTML.
        return self._prepare_prompt_for_html_text(content)

    return None

  def get_results(self,
                  benchmark: str) -> tuple[list[evaluator.Result], list[str]]:
    """
    Returns results of all samples. Items can be None if they're not complete.
    """
    targets = self._get_generated_targets(benchmark)

    results = []
    status_dir = os.path.join(self._results_dir, benchmark, 'status')

    for sample_id in self._sample_ids(targets):
      results_path = os.path.join(status_dir, sample_id, 'result.json')
      if not FileSystem(results_path).exists():
        results.append(None)
        continue

      with FileSystem(results_path).open() as f:
        try:
          data = json.load(f)
        except Exception:
          return [], []

      results.append(evaluator.Result(**data))

    return results, targets

  def get_macro_insights(self,
                         benchmarks: list[Benchmark]) -> AccumulatedResult:
    """Returns macro insights from the aggregated benchmark results."""
    accumulated_results = AccumulatedResult()
    for benchmark in benchmarks:
      accumulated_results.compiles += int(
          benchmark.result.build_success_rate > 0.0)
      accumulated_results.crashes += int(benchmark.result.found_bug > 0)
      accumulated_results.total_coverage += benchmark.result.max_coverage
      accumulated_results.total_runs += 1
      accumulated_results.total_line_coverage_diff += benchmark.result.max_line_coverage_diff
    return accumulated_results

  def _prepare_prompt_for_html_text(self, raw_prompt_content: str) -> str:
    """Converts a raw prompt file into presentable HTML text."""
    try:
      structured_prompt = json.loads(raw_prompt_content)
      if isinstance(structured_prompt, list) and structured_prompt:
        html_presentable_content = ''
        for elem in structured_prompt:
          if isinstance(elem, dict) and 'content' in elem:
            html_presentable_content += f'\n{elem["content"]}'
        logging.debug('Converted structured prompt to raw text.')
        return html_presentable_content
    except json.decoder.JSONDecodeError:
      logging.debug('Using raw prompt text.')
      pass

    # If execution goes here it the input was not a structured prompt but just
    # raw text, which is then returned.
    return raw_prompt_content

  def _is_valid_benchmark_dir(self, cur_dir: str) -> bool:
    """Checks if |cur_dir| is a valid benchmark directory (e.g., no lost+found)."""
    # Check prefix.
    if not cur_dir.startswith('output-'):
      return False

    # Skip checking sub-directories in GCS. It's a lot of filesystem operations
    # to go over the network.
    if cur_dir.startswith('gs://'):
      return True

    # Check sub-directories.
    expected_dirs = ['raw_targets', 'status', 'fixed_targets']
    return all(
        FileSystem(os.path.join(self._results_dir, cur_dir,
                                expected_dir)).isdir()
        for expected_dir in expected_dirs)

  def _get_generated_targets(self, benchmark: str) -> list[str]:
    targets = []
    raw_targets_dir = os.path.join(self._results_dir, benchmark, 'raw_targets')
    for filename in sorted(FileSystem(raw_targets_dir).listdir()):
      if os.path.splitext(filename)[1] in TARGET_EXTS:
        targets.append(os.path.join(raw_targets_dir, filename))

    return targets

  def _get_fixed_target(self, path: str):
    """Gets the fixed fuzz target from the benchmark's result |path|."""
    code = ''
    fixer_prompt = ''
    for name in FileSystem(path).listdir():
      if name.endswith('.txt'):
        with FileSystem(os.path.join(path, name)).open() as f:
          fixer_prompt = f.read()

      # Prepare prompt for being used in HTML.
      fixer_prompt = self._prepare_prompt_for_html_text(fixer_prompt)

      if name.endswith('.rawoutput'):
        with FileSystem(os.path.join(path, name)).open() as f:
          code = f.read()

    return Target(code, fixer_prompt)

  def _sample_ids(self, target_paths: list[str]):
    for target in target_paths:
      yield os.path.splitext(os.path.basename(target))[0]

  def _create_benchmark(
      self, benchmark_id: str, status: str,
      result: run_one_experiment.AggregatedResult) -> Benchmark:
    project = '-'.join(benchmark_id.split('-')[1:-1])
    function = benchmark_id.split('-')[-1]
    signature = self._find_benchmark_signature(project,
                                               function) or benchmark_id
    return Benchmark(benchmark_id, status, result, signature, project, function)

  def _find_benchmark_signature(self, project: str,
                                target_function: str) -> str:
    """Finds the function signature by searching for its |benchmark_id|."""
    project_path = os.path.join(self._benchmark_dir, f'{project}.yaml')
    if not FileSystem(project_path).isfile():
      return ''

    matched_prefix_signature = ''
    with FileSystem(project_path).open() as project_yaml_file:
      functions = yaml.safe_load(project_yaml_file).get('functions', [])
      for function in functions:
        function_name = function.get('name', '')
        function_signature = function.get('signature', '')

        # Best match is a full match, but sometimes the result directory only
        # has the first n characters of a long function name so a full match is
        # not possible.
        # To avoid returning early on a prefix match when there is a full match
        # farther down the list, we only return the prefix match at the end.
        if function_name.lower() == target_function.lower():
          return function_signature
        if function_name.lower().startswith(target_function.lower()):
          if matched_prefix_signature:
            logging.warning(
                'Multiple substring matches found when looking for function '
                'name %s', function_name)
          matched_prefix_signature = function_signature

    return matched_prefix_signature
