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
import random
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional

import requests
from google.cloud import storage

from data_prep import project_src
from experiment import benchmark as benchmarklib
from experiment import oss_fuzz_checkout

TIMEOUT = 10
MAX_RETRY = 5
INTROSPECTOR_ENDPOINT = 'https://introspector.oss-fuzz.com/api'
INTROSPECTOR_CFG = f'{INTROSPECTOR_ENDPOINT}/annotated-cfg'
INTROSPECTOR_FUNCTION = f'{INTROSPECTOR_ENDPOINT}/far-reach-but-low-coverage'
INTROSPECTOR_SOURCE = f'{INTROSPECTOR_ENDPOINT}/function-source-code'
INTROSPECTOR_XREF = f'{INTROSPECTOR_ENDPOINT}/all-cross-references'
INTROSPECTOR_TYPE = f'{INTROSPECTOR_ENDPOINT}/type-info'
INTROSPECTOR_FUNC_SIG = f'{INTROSPECTOR_ENDPOINT}/function-signature'


def _query_introspector(api: str, params: dict) -> dict:
  """Queries FuzzIntrospector API and returns the json payload,
  returns an empty dict if unable to get data."""
  for attempt_num in range(1, MAX_RETRY + 1):
    try:
      resp = requests.get(api, params, timeout=TIMEOUT)
      if not resp.ok:
        logging.error(
            'Failed to get data from FI:\n'
            '%s\n'
            '-----------Response received------------\n'
            '%s\n'
            '------------End of response-------------', resp.url,
            resp.content.decode('utf-8').strip())
        break
      return resp.json()
    except requests.exceptions.Timeout as err:
      if attempt_num == MAX_RETRY:
        logging.error(
            'Failed to get data from FI due to timeout, max retry exceeded:\n'
            'API: %s, params: %s\n'
            'Error: %s', api, params, err)
        break
      delay = 5 * 2**attempt_num + random.randint(1, 10)
      logging.warning(
          'Failed to get data from FI due to timeout on attempt %d, '
          'retry in %ds...', attempt_num, delay)
      time.sleep(delay)
    except requests.exceptions.RequestException as err:
      logging.error('Failed to get data from FI, unexpected error: %s', err)
      break

  return {}


def query_introspector_for_unreached_functions(project: str) -> list[dict]:
  """Queries FuzzIntrospector API for unreached functions in |project|."""
  data = _query_introspector(INTROSPECTOR_FUNCTION, {'project': project})
  functions = data.get('functions')
  if functions:
    return functions
  logging.error('No functions found from FI for project %s:\n  %s', project,
                '\n  '.join(data.get('extended_msgs', [])))
  sys.exit(1)


def query_introspector_cfg(project: str) -> dict:
  """Queries FuzzIntrospector API for CFG."""
  return _query_introspector(INTROSPECTOR_CFG, {
      'project': project
  }).get('project', {})


def query_introspector_function_source(project: str, func_sig: str) -> str:
  """Queries FuzzIntrospector API for source code of |func_sig|."""
  data = _query_introspector(INTROSPECTOR_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  source = data.get('source', '')
  if not source:
    logging.error('No function source found for %s in %s: %s', func_sig,
                  project, data)

  return source


def query_introspector_cross_references(project: str,
                                        func_sig: str) -> list[str]:
  """Queries FuzzIntrospector API for source code of functions
  cross-referenced |func_sig|."""
  data = _query_introspector(INTROSPECTOR_XREF, {
      'project': project,
      'function_signature': func_sig
  })
  call_sites = data.get('callsites', [])

  xref_source = []
  for cs in call_sites:
    name = cs.get('dst_func')
    sig = query_introspector_function_signature(project, name)
    source = query_introspector_function_source(project, sig)
    xref_source.append(source)
  return xref_source


def query_introspector_type_info(project: str, type_name: str) -> dict:
  """Queries FuzzIntrospector API for information of |type_name|."""
  data = _query_introspector(INTROSPECTOR_TYPE, {
      'project': project,
      'name': type_name
  })
  type_info = data.get('type_data', {})
  if not type_info:
    logging.error('No type info found from FI for %s in %s: %s', type_name,
                  project, data)

  return type_info


def query_introspector_function_signature(project: str,
                                          function_name: str) -> str:
  """Queries FuzzIntrospector API for signature of |function_name|."""
  data = _query_introspector(INTROSPECTOR_FUNC_SIG, {
      'project': project,
      'function': function_name
  })
  func_sig = data.get('signature', '')
  if not func_sig:
    logging.error('No signature found from FI for %s in %s: %s', function_name,
                  project, data)

  return func_sig


def get_unreached_functions(project):
  functions = query_introspector_for_unreached_functions(project)
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


def _get_raw_return_type(function: dict, project: str) -> str:
  """Returns the raw function type."""
  return_type = function.get('return-type') or function.get('return_type', '')
  if not return_type:
    logging.error(
        'Missing return type in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return return_type


def _get_clean_return_type(function: dict, project: str) -> str:
  """Returns the cleaned function type."""
  raw_return_type = _get_raw_return_type(function, project).strip()
  if raw_return_type == 'N/A':
    # Bug in introspector: Unable to distinguish between bool and void right
    # now. More likely to be void for function return arguments.
    return 'void'
  return clean_type(raw_return_type)


def get_raw_function_name(function: dict, project: str) -> str:
  """Returns the raw function name."""
  raw_name = (function.get('raw-function-name') or
              function.get('raw_function_name', ''))
  if not raw_name:
    logging.error('No raw function name in project: %s for function: %s',
                  project, function)
  return raw_name


def _get_clean_arg_types(function: dict, project: str) -> list[str]:
  """Returns the cleaned function argument types."""
  raw_arg_types = (function.get('arg-types') or
                   function.get('function_arguments', []))
  if not raw_arg_types:
    logging.error(
        'Missing argument types in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return [clean_type(arg_type) for arg_type in raw_arg_types]


def _get_arg_names(function: dict, project: str) -> list[str]:
  """Returns the function argument names."""
  arg_names = (function.get('arg-names') or
               function.get('function_argument_names', []))
  if not arg_names:
    logging.error(
        'Missing argument names in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return arg_names


def get_function_signature(function: dict, project: str) -> str:
  """Returns the function signature."""
  function_signature = function.get('function_signature', '')
  if not function_signature:
    logging.error(
        'Missing function signature in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return function_signature


# TODO(dongge): Remove this function when FI fixes it.
def _parse_type_from_raw_tagged_type(tagged_type: str) -> str:
  """Returns type name from |tagged_type| such as struct.TypeA"""
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
  result = project_src.search_source(project, filenames)
  if not result:
    return []

  harnesses, interesting = result
  harness = pick_one(harnesses)
  if not harness:
    logging.error('No fuzz target found in project %s.', project)
    return []
  logging.info('Fuzz target file found for project %s: %s', project, harness)
  target_name = get_target_name(project, harness)
  logging.info('Fuzz target binary found for project %s: %s', project,
               target_name)

  potential_benchmarks = []
  for function in functions:
    filename = os.path.basename(function['function_filename'])
    if filename not in [os.path.basename(i) for i in interesting]:
      # TODO: Bazel messes up paths to include "/proc/self/cwd/..."
      logging.error('error: %s %s', filename, interesting.keys())
      continue
    function_signature = get_function_signature(function, project)
    if not function_signature:
      continue
    logging.info('Function signature to fuzz: %s', function_signature)
    potential_benchmarks.append(
        benchmarklib.Benchmark('cli',
                               project,
                               language,
                               function_signature,
                               get_raw_function_name(function, project),
                               _get_clean_return_type(function, project),
                               _group_function_params(
                                   _get_clean_arg_types(function, project),
                                   _get_arg_names(function, project)),
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


def _postprocess_function(target_func: dict, project_name: str):
  """Post-processes target function."""
  target_func['return-type'] = _get_clean_return_type(target_func, project_name)
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
      _postprocess_function(target_func, project_name)
      fuzz_target_funcs[fuzz_target_file].append(target_func)

  # Sort functions in each target file by their complexity.
  # Assume the most complex functions are the ones under test,
  # put them at the beginning.
  for file, funcs in fuzz_target_funcs.items():
    fuzz_target_funcs[file] = sorted(
        funcs, key=lambda f: f.get('cyclomatic-complexity'), reverse=True)
  return fuzz_target_funcs


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)

  # TODO(Dongge): Use argparser.
  cur_project = sys.argv[1]
  max_num_function = 3
  if len(sys.argv) > 2:
    max_num_function = int(sys.argv[2])
  if len(sys.argv) > 3:
    outdir = sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
  else:
    outdir = ''

  try:
    oss_fuzz_checkout.clone_oss_fuzz()
    oss_fuzz_checkout.postprocess_oss_fuzz()
  except subprocess.CalledProcessError as e:
    logging.error('Failed to prepare OSS-Fuzz directory for project %s: %s',
                  sys.argv[1], e)
  cur_project_language = oss_fuzz_checkout.get_project_language(cur_project)
  benchmarks = populate_benchmarks_using_introspector(cur_project,
                                                      cur_project_language,
                                                      max_num_function)
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, outdir)
  else:
    logging.error('Nothing found for %s', sys.argv[1])
    sys.exit(1)
