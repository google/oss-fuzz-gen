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
import inspect
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

TARGET_EXTS = project_src.SEARCH_EXTS + ['.java', '.py'] + ['.fuzz_target']

_CHAT_PROMPT_START_MARKER = re.compile(r'<CHAT PROMPT:ROUND\s+\d+>')
_CHAT_PROMPT_END_MARKER = re.compile(r'</CHAT PROMPT:ROUND\s+\d+>')
_CHAT_RESPONSE_START_MARKER = re.compile(r'<CHAT RESPONSE:ROUND\s+\d+>')
_CHAT_RESPONSE_END_MARKER = re.compile(r'</CHAT RESPONSE:ROUND\s+\d+>')


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
class Project:
  """Results for a project entire."""
  name: str
  count: int = 0
  success: int = 0
  coverage_gain: float = 0.0
  coverage_relative_gain: float = 0.0
  coverage_ofg_total_new_covered_lines = 0
  coverage_existing_total_covered_lines = 0
  coverage_existing_total_lines = 0
  coverage_ofg_total_covered_lines = 0


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


@dataclasses.dataclass
class Triage:
  result: str
  triager_prompt: str


@dataclasses.dataclass
class LogPart:
  chat_prompt: bool = False
  chat_response: bool = False
  content: str = ''


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
  """Results provides functions to explore the experiment results in a
  particular directory."""

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
    # TODO(donggeliu): Make this consistent with agent output.
    if not os.path.exists(targets_dir):
      return ''

    for name in sorted(FileSystem(targets_dir).listdir()):
      path = os.path.join(targets_dir, name)
      if name.startswith(sample + '.') and FileSystem(path).isfile():
        with FileSystem(path).open() as f:
          code = f.read()
          code = json.dumps(code)
        return code
    return ''

  def get_logs(self, benchmark: str, sample: str) -> list[LogPart]:
    status_dir = os.path.join(self._results_dir, benchmark, 'status')
    results_path = os.path.join(status_dir, sample, 'log.txt')
    if not FileSystem(results_path).exists():
      return []

    with FileSystem(results_path).open() as f:
      return _parse_log_parts(f.read())

  def get_run_logs(self, benchmark: str, sample: str) -> str:
    """Returns the content of the last run log."""
    run_logs_dir = os.path.join(self._results_dir, benchmark, 'logs', 'run')
    largest_iteration, last_log_file = -1, None
    for name in FileSystem(run_logs_dir).listdir():
      if name.startswith(sample + '.'):
        iteration = WorkDirs.get_run_log_iteration(name)
        if iteration is None:
          # Be compatible with older results where there is no '-Fxx' in run
          # log file name.
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

  def get_triage(self, benchmark: str, sample: str) -> Triage:
    """Gets the triage of benchmark |benchmark| with sample ID |sample|."""
    result = ''
    triager_prompt = ''
    fixed_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')
    triage_dir = os.path.join(fixed_dir, f'{sample}-triage')
    if not os.path.exists(triage_dir):
      return Triage(result, triager_prompt)

    for name in os.listdir(triage_dir):
      if name == 'prompt.txt':
        with FileSystem(os.path.join(triage_dir, name)).open() as f:
          triager_prompt = f.read()

        # Prepare prompt for being used in HTML.
        triager_prompt = self._prepare_prompt_for_html_text(triager_prompt)

      if name.endswith('.txt') and name != 'prompt.txt':
        triage_path = os.path.join(triage_dir, name)
        with open(triage_path) as f:
          result = f.read()

    return Triage(result, triager_prompt)

  def get_targets(self, benchmark: str, sample: str) -> list[Target]:
    """Gets the targets of benchmark |benchmark| with sample ID |sample|."""
    return (self._get_targets(benchmark, sample) or
            [self._get_targets_agent(benchmark, sample)])

  def _get_targets(self, benchmark: str, sample: str) -> list[Target]:
    """Gets the targets of benchmark |benchmark| with sample ID |sample| from
    the OFG version 1 (single prompt)."""
    targets_dir = os.path.join(self._results_dir, benchmark, 'fixed_targets')
    # TODO(donggeliu): Make this consistent with agent output.
    if not os.path.exists(targets_dir):
      return []

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

  def _get_targets_agent(self, benchmark: str, trial: str) -> Target:
    """Gets the targets of benchmark |benchmark| with trial ID |trial| from
    the OFG version 2 (LLM agents)."""
    fuzz_target_dir = os.path.join(self._results_dir, benchmark, 'fuzz_targets')
    files = sorted(FileSystem(fuzz_target_dir).listdir())

    fuzz_target_code = ''
    if f'{trial:02s}.fuzz_target' in files:
      fuzz_target_path = os.path.join(fuzz_target_dir,
                                      f'{trial:02s}.fuzz_target')
      with FileSystem(fuzz_target_path).open() as f:
        fuzz_target_code = f.read()

    build_script_code = ''
    if f'{trial:02s}.build_script' in files:
      build_script_path = os.path.join(fuzz_target_dir,
                                       f'{trial:02s}.build_script')
      with FileSystem(build_script_path).open() as f:
        build_script_code = f.read()

    # TODO(dongge): Properly show build script code in reports.
    return Target(code=fuzz_target_code, fixer_prompt=build_script_code)

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
    """Gets the prompt for a given benchmark."""
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
    targets = self._get_generated_targets(
        benchmark) or self._get_agent_generated_targets(benchmark)

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

      # TODO(dongge): Add new attributes to evaluator.Result.
      valid_attributes = inspect.signature(evaluator.Result.__init__).parameters
      filtered_data = {
          key: value for key, value in data.items() if key in valid_attributes
      }
      results.append(evaluator.Result(**filtered_data))

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
      accumulated_results.total_line_coverage_diff += (
          benchmark.result.max_line_coverage_diff)
    return accumulated_results

  def get_coverage_language_gains(self):
    """Gets report.json created by experiment runners."""
    summary_path = os.path.join(self._results_dir, 'report.json')
    if FileSystem(summary_path).exists():
      with FileSystem(summary_path).open() as f:
        try:
          return json.load(f)
        except ValueError:
          # Skip if error
          logging.debug('Failed to decode project_coverage_gain.json')
    return {}

  def get_project_summary(self, benchmarks: list[Benchmark]) -> list[Project]:
    """Returns a list of project summary."""
    project_summary_dict = {}
    for benchmark in benchmarks:
      if benchmark.project not in project_summary_dict:
        project_summary_dict[benchmark.project] = Project(benchmark.project)
      project_summary_dict[benchmark.project].count += 1
      project_summary_dict[benchmark.project].success += (
          benchmark.result.build_success_count > 0)

    # Retrieve coverage gain information
    coverage_dict = {}
    summary_path = os.path.join(self._results_dir, 'report.json')
    if FileSystem(summary_path).exists():
      with FileSystem(summary_path).open() as f:
        try:
          coverage_dict = json.load(f).get('project_summary', {})
        except ValueError:
          # Skip if error
          logging.debug('Failed to decode project_coverage_gain.json')

    # Update project summary with coverage gain information
    project_summary_list = list(project_summary_dict.values())
    if coverage_dict:
      for project in project_summary_list:
        if project.name in coverage_dict:
          project.coverage_gain = coverage_dict[project.name]['coverage_diff']
          project.coverage_relative_gain = coverage_dict[
              project.name]['coverage_relative_gain']
          project.coverage_ofg_total_new_covered_lines = coverage_dict[
              project.name]['coverage_ofg_total_new_covered_lines']
          project.coverage_existing_total_covered_lines = coverage_dict[
              project.name]['coverage_existing_total_covered_lines']
          project.coverage_existing_total_lines = coverage_dict[
              project.name]['coverage_existing_total_lines']
          project.coverage_ofg_total_covered_lines = coverage_dict[
              project.name]['coverage_ofg_total_covered_lines']

    return project_summary_list

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

    # If execution goes here it the input was not a structured prompt but just
    # raw text, which is then returned.
    return raw_prompt_content

  def _is_valid_benchmark_dir(self, cur_dir: str) -> bool:
    """Checks if |cur_dir| is a valid benchmark directory (e.g., no lost+found).
    """
    # Check prefix.
    if not cur_dir.startswith('output-'):
      return False

    # Skip checking sub-directories in GCS. It's a lot of filesystem operations
    # to go over the network.
    if cur_dir.startswith('gs://'):
      return True

    # Check sub-directories.
    # TODO(donggeliu): Make this consistent with agent output.
    # We used to expect 'fixed_targets' and 'raw_targets' here, but the agent
    # workflow doesn't populate them. As a result, these directories don't get
    # uploaded to GCS.
    expected_dirs = ['status']
    return all(
        FileSystem(os.path.join(self._results_dir, cur_dir,
                                expected_dir)).isdir()
        for expected_dir in expected_dirs)

  # TODO(dongge): Deprecate this.
  def _get_generated_targets(self, benchmark: str) -> list[str]:
    """Gets the targets of benchmark |benchmark| from the OFG version 1 (single
    prompt)."""
    targets = []
    raw_targets_dir = os.path.join(self._results_dir, benchmark, 'raw_targets')
    # TODO(donggeliu): Make this consistent with agent output.
    if not os.path.exists(raw_targets_dir):
      return []

    for filename in sorted(FileSystem(raw_targets_dir).listdir()):
      if os.path.splitext(filename)[1] in TARGET_EXTS:
        targets.append(os.path.join(raw_targets_dir, filename))

    return targets

  def _get_agent_generated_targets(self, benchmark: str) -> list[str]:
    """Gets the targets of benchmark |benchmark| from the OFG version 2 (LLM
    agent)."""
    targets = []
    fuzz_targets_dir = os.path.join(self._results_dir, benchmark,
                                    'fuzz_targets')
    for filename in sorted(FileSystem(fuzz_targets_dir).listdir()):
      if os.path.splitext(filename)[1] in TARGET_EXTS:
        targets.append(os.path.join(fuzz_targets_dir, filename))

    return targets

  def _get_fixed_target(self, path: str) -> Target:
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


def _parse_log_parts(log: str) -> list[LogPart]:
  """Parse log into parts."""
  parts = []
  idx = 0
  next_marker = _CHAT_PROMPT_START_MARKER

  while idx < len(log):
    match = next_marker.search(log, idx)
    if not match:
      parts.append(LogPart(content=log[idx:]))
      break

    if match.start() > idx:
      # Log content in between chat logs.
      parts.append(LogPart(content=log[idx:match.start()]))

    # Read up to the start of the corresponding end marker.
    end_idx = len(log)

    chat_prompt = False
    chat_response = False
    if next_marker == _CHAT_PROMPT_START_MARKER:
      end = _CHAT_PROMPT_END_MARKER.search(log, match.end())
      chat_prompt = True
      next_marker = _CHAT_RESPONSE_START_MARKER
    else:
      assert next_marker == _CHAT_RESPONSE_START_MARKER
      end = _CHAT_RESPONSE_END_MARKER.search(log, match.end())
      chat_response = True
      next_marker = _CHAT_PROMPT_START_MARKER

    if end:
      end_idx = end.start()
      # Skip past the end tag.
      idx = end.end()
    else:
      # No corresponding end tag, just read till the end of the log.
      end_idx = len(log)
      idx = end_idx

    parts.append(
        LogPart(chat_prompt=chat_prompt,
                chat_response=chat_response,
                content=log[match.end():end_idx]))

  return parts
