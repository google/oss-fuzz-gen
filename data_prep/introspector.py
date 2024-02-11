#!/usr/bin/env python3
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
"""Interacts with FuzzIntrospector APIs"""

import json
import logging
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional

import requests
from google.cloud import storage

from data_prep import project_src
from experiment import benchmark as benchmarklib
from experiment import oss_fuzz_checkout

TIMEOUT = 10
INTROSPECTOR_ENDPOINT = 'https://introspector.oss-fuzz.com/api'
INTROSPECTOR_CFG = f'{INTROSPECTOR_ENDPOINT}/annotated-cfg'
INTROSPECTOR_FUNCTION = f'{INTROSPECTOR_ENDPOINT}/far-reach-but-low-coverage'


def query_introspector(project):
  resp = requests.get(INTROSPECTOR_FUNCTION,
                      params={'project': project},
                      timeout=TIMEOUT)
  data = resp.json()
  functions = data.get('functions')
  if functions:
    return functions
  logging.error('No functions found from FI for project %s:\n  %s', project,
                '\n  '.join(data.get('extended_msgs')))
  sys.exit(1)


def query_introspector_cfg(project):
  resp = requests.get(INTROSPECTOR_CFG,
                      params={'project': project},
                      timeout=TIMEOUT)
  data = resp.json()
  return data.get('project', {})


def get_unreached_functions(project):
  functions = query_introspector(project)
  functions = [f for f in functions if not f['reached_by_fuzzers']]
  return functions


def demangle(name: str) -> str:
  return subprocess.run(['c++filt', name],
                        check=True,
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        text=True).stdout.strip()


def clean_type(name: str) -> str:
  """Fix comment function type mistakes from FuzzIntrospector."""
  if name == 'N/A':
    # Seems to be a bug in introspector:
    # https://github.com/ossf/fuzz-introspector/issues/1188
    return 'bool '

  name = name.replace('struct.', 'struct ')
  name = name.replace('class.', '')
  name = name.replace('__1::basic_', '')
  name = name.replace('__1::', '')
  # Introspector sometimes includes numeric suffixes to struct names.
  name = re.sub(r'(\.\d+)+(\s*\*)$', r'\2', name)
  name.strip()
  return name


def _get_raw_return_type(function: dict) -> str:
  """Returns the raw function type."""
  return function.get('return-type') or function.get('return_type', '')


def _get_clean_return_type(function: dict) -> str:
  """Returns the cleaned function type."""
  raw_return_type = _get_raw_return_type(function).strip()
  if raw_return_type == 'N/A':
    # Bug in introspector: Unable to distinguish between bool and void right
    # now. More likely to be void for function return arguments.
    return 'void'
  return clean_type(raw_return_type)


def _get_raw_function_name(function: dict) -> str:
  """Returns the raw function name."""
  return (function.get('raw-function-name') or
          function.get('raw_function_name', ''))


def _get_demangled_function_name(function: dict) -> str:
  """Returns the demangled function name."""
  return demangle(_get_raw_function_name(function))


def _get_minimized_function_name(function: dict) -> str:
  """Minimizes C++ function name by removing parameters."""
  # Assumption: <return_type><function_name><templare specialization> is unique.
  function_name = _get_demangled_function_name(function)
  depth = 0
  for i, char in enumerate(function_name):
    depth += char == '<'
    depth -= char == '>'
    if char == '(' and depth == 0:
      # Split at the first '(' that's not within template specialization.
      function_name = function_name[:i]
  return function_name.replace(' ', '')


def _get_clean_arg_types(function: dict) -> list[str]:
  """Returns the cleaned function argument types."""
  raw_arg_types = (function.get('arg-types') or
                   function.get('function_arguments', ''))
  return [clean_type(arg_type) for arg_type in raw_arg_types]


def _get_arg_names(function: dict) -> list[str]:
  """Returns the cleaned function argument types."""
  return (function.get('arg-names') or
          function.get('function_argument_names', ''))


def formulate_function_signature(function: dict, language: str) -> str:
  """Formulates a function signature based on its |function| dictionary."""
  # C++ functions, get signature from c++filt.
  if language == benchmarklib.FileType.CPP.value.lower():
    return _get_demangled_function_name(function)

  # Plain C function.
  return_type = _get_clean_return_type(function)
  function_arg_types = _get_clean_arg_types(function)
  function_arg_names = _get_arg_names(function)

  args_signature = ', '.join([
      f'{arg_type} {arg_name}'
      for arg_type, arg_name in zip(function_arg_types, function_arg_names)
  ])
  return f'{return_type} {_get_raw_function_name(function)}({args_signature})'


# TODO(dongge): Remove this function when FI fixes it.
def _parse_type_from_raw_tagged_type(tagged_type: str) -> str:
  """Returns type name from |targged_type| such as struct.TypeA"""
  # Assume: Types do not contain dot(.).
  return tagged_type.split('.')[-1]


def _group_function_params(param_types: list[str],
                           param_names: list[str]) -> list[dict[str, str]]:
  """Groups the type and name of each parameter."""
  return [{
      'type': _parse_type_from_raw_tagged_type(param_type),
      'name': param_name
  } for param_type, param_name in zip(param_types, param_names)]


def populate_benchmarks_using_introspector(project: str, language: str,
                                           limit: int):
  """Populates benchmark YAML files from the data from FuzzIntrospector."""
  functions = get_unreached_functions(project)
  if not functions:
    logging.error('No unreached functions found')
    return []

  filenames = [
      os.path.basename(function['function_filename']) for function in functions
  ]
  #  logging.info([f['function-name'] for f in functions])
  result = project_src.search_source(project, filenames)
  if not result:
    return []

  harnesses, interesting = result
  harness = pick_one(harnesses)
  if not harness:
    logging.error('No fuzz target found in project %s.', project)
    return []
  logging.info('Fuzz target found for project %s: %s', project, harness)
  target_name = get_target_name(project, harness)
  logging.info('Fuzz target found for project %s: %s', project, target_name)

  potential_benchmarks = []
  for function in functions:
    filename = os.path.basename(function['function_filename'])
    if filename not in [os.path.basename(i) for i in interesting]:
      # TODO: Bazel messes up paths to include "/proc/self/cwd/..."
      logging.error('error: %s %s', filename, interesting.keys())
      continue
    # TODO(dongge): Remove this line when FI provides function_signature.
    function_signature = formulate_function_signature(function, language)
    if not function_signature:
      continue
    logging.info('Function signature to fuzz: %s', function_signature)
    potential_benchmarks.append(
        benchmarklib.Benchmark('cli',
                               project,
                               language,
                               function_signature,
                               _get_minimized_function_name(function),
                               _get_clean_return_type(function),
                               _group_function_params(
                                   _get_clean_arg_types(function),
                                   _get_arg_names(function)),
                               harness,
                               target_name,
                               function_dict=function))

    if len(potential_benchmarks) >= limit:
      break

  return potential_benchmarks


def pick_one(d: dict):
  if not d:
    return None
  return list(d.keys())[0]


def get_target_name(project_name: str, harness: str) -> Optional[str]:
  """Gets the matching target name."""
  summary = query_introspector_cfg(project_name)
  for annotated in summary.get('annotated_cfg', []):
    if annotated['source_file'] == harness:
      return annotated['fuzzer_name']

  return None


##### Helper logic for downloading fuzz introspector reports.
# Download introspector report.
def _identify_latest_report(project_name: str):
  """Returns the latest summary in the FuzzIntrospector bucket."""
  client = storage.Client.create_anonymous_client()
  bucket = client.get_bucket('oss-fuzz-introspector')
  blobs = bucket.list_blobs(prefix=project_name)
  summaries = sorted(
      [blob.name for blob in blobs if blob.name.endswith('summary.json')])
  if summaries:
    return ('https://storage.googleapis.com/oss-fuzz-introspector/'
            f'{summaries[-1]}')
  logging.error('Error: %s has no summary.', project_name)
  return None


def _extract_introspector_report(project_name):
  """Queries and extracts FuzzIntrospector report data of |project_name|."""
  project_url = _identify_latest_report(project_name)
  if not project_url:
    return None
  # Read the introspector artifact.
  try:
    raw_introspector_json_request = requests.get(project_url, timeout=10)
    introspector_report = json.loads(raw_introspector_json_request.text)
  except:
    return None
  return introspector_report


def _contains_function(funcs: List[Dict], target_func: Dict):
  """Returns True if |funcs| contains |target_func|, vice versa."""
  key_fields = ['function-name', 'source-file', 'return-type', 'arg-list']
  for func in funcs:
    if all(func.get(field) == target_func.get(field) for field in key_fields):
      return True
  return False


def _postprocess_function(target_func: Dict):
  """Post-processes target function."""
  target_func['return-type'] = _get_clean_return_type(target_func)
  target_func['function-name'] = demangle(target_func['function-name'])


def get_project_funcs(project_name: str) -> Dict[str, List[Dict]]:
  """Fetches the latest fuzz targets and function signatures of |project_name|
    from FuzzIntrospector."""
  introspector_json_report = _extract_introspector_report(project_name)
  if introspector_json_report is None:
    print('Error: No fuzz introspector report is found.')
    return {}

  if introspector_json_report.get('analyses') is None:
    logging.error('Error: introspector_json_report has no "analyses"')
    return {}
  if introspector_json_report.get('analyses').get('AnnotatedCFG') is None:
    logging.error(
        'Error: introspector_json_report["analyses"] has no "AnnotatedCFG"')
    return {}

  # Group functions by target files.
  annotated_cfg = introspector_json_report.get('analyses').get('AnnotatedCFG')
  fuzz_target_funcs = {}
  for fuzzer in annotated_cfg:
    for target_func in annotated_cfg[fuzzer]['destinations']:
      # Remove functions where there are no source file, e.g. libc functions
      if target_func['source-file'] == '':
        continue

      # Group functions by fuzz target source code file, because there may
      # be multiple functions in the same fuzz target file.
      fuzz_target_file = annotated_cfg[fuzzer]['src_file']
      if fuzz_target_file not in fuzz_target_funcs:
        fuzz_target_funcs[fuzz_target_file] = []
      if _contains_function(fuzz_target_funcs[fuzz_target_file], target_func):
        continue
      _postprocess_function(target_func)
      fuzz_target_funcs[fuzz_target_file].append(target_func)

  # Sort functions in each target file by their complexity.
  # Assume the most complex functions are the ones under test,
  # put them at the beginning.
  for file, funcs in fuzz_target_funcs.items():
    fuzz_target_funcs[file] = sorted(
        funcs, key=lambda f: f.get('cyclomatic-complexity'), reverse=True)
  return fuzz_target_funcs


if __name__ == '__main__':
  # Usage: python3 introspector.py <oss-fuzz-project-name>
  logging.basicConfig(level=logging.INFO)

  #TODO(Dongge): Use argparser.
  cur_project = sys.argv[1]
  max_num_function = 3
  if len(sys.argv) > 2:
    max_num_function = int(sys.argv[2])
  if len(sys.argv) > 3:
    outdir = sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
  else:
    outdir = ''

  oss_fuzz_checkout.clone_oss_fuzz()
  oss_fuzz_checkout.postprocess_oss_fuzz()
  cur_project_language = oss_fuzz_checkout.get_project_language(cur_project)
  benchmarks = populate_benchmarks_using_introspector(cur_project,
                                                      cur_project_language,
                                                      max_num_function)
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, outdir)
  else:
    logging.error('Nothing found for %s', sys.argv[1])
    sys.exit(1)
