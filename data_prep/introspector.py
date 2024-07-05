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

import argparse
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, OrderedDict, TypeVar
from urllib.parse import urlencode

import requests
from google.cloud import storage

from data_prep import project_src
from experiment import benchmark as benchmarklib
from experiment import oss_fuzz_checkout

T = TypeVar('T', str, list, dict, int)  # Generic type.

TIMEOUT = 45
MAX_RETRY = 5

# By default exclude static functions when identifying fuzz target candidates
# to generate benchmarks.
ORACLE_AVOID_STATIC_FUNCTIONS = bool(
    int(os.getenv('OSS_FUZZ_AVOID_STATIC_FUNCTIONS', '1')))
ORACLE_ONLY_REFERENCED_FUNCTIONS = bool(
    int(os.getenv('OSS_FUZZ_ONLY_REFERENCED_FUNCTIONS', '0')))
ORACLE_ONLY_FUNCTIONS_WITH_HEADER_DECLARATIONS = bool(
    int(os.getenv('OSS_FUZZ_ONLY_FUNCS_WITH_HEADER_DECLARATION', '1')))

DEFAULT_INTROSPECTOR_ENDPOINT = 'https://introspector.oss-fuzz.com/api'
INTROSPECTOR_ENDPOINT = ''
INTROSPECTOR_CFG = ''
INTROSPECTOR_ORACLE_FAR_REACH = ''
INTROSPECTOR_ORACLE_KEYWORD = ''
INTROSPECTOR_ORACLE_EASY_PARAMS = ''
INTROSPECTOR_ORACLE_ALL_JVM_PUBLIC_CANDIDATES = ''
INTROSPECTOR_ORACLE_OPTIMAL = ''
INTROSPECTOR_FUNCTION_SOURCE = ''
INTROSPECTOR_PROJECT_SOURCE = ''
INTROSPECTOR_XREF = ''
INTROSPECTOR_TYPE = ''
INTROSPECTOR_FUNC_SIG = ''
INTROSPECTOR_ADDR_TYPE = ''
INTROSPECTOR_ALL_HEADER_FILES = ''
INTROSPECTOR_ALL_FUNC_TYPES = ''
INTROSPECTOR_HEADERS_FOR_FUNC = ''
INTROSPECTOR_SAMPLE_XREFS = ''
INTROSPECTOR_ALL_JVM_SOURCE_PATH = ''
INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE = ''


def get_oracle_dict() -> Dict[str, Any]:
  """Returns the oracles available to identify targets."""
  # Do this in a function to allow for forward-declaration of functions below.
  oracle_dict = {
      'far-reach-low-coverage': get_unreached_functions,
      'low-cov-with-fuzz-keyword': query_introspector_for_keyword_targets,
      'easy-params-far-reach': query_introspector_for_easy_param_targets,
      'jvm-public-candidates': query_introspector_jvm_all_public_candidates,
      'optimal-targets': query_introspector_for_optimal_targets,
  }
  return oracle_dict


def set_introspector_endpoints(endpoint):
  """Sets URLs for Fuzz Introspector endpoints to local or remote endpoints."""
  global INTROSPECTOR_ENDPOINT, INTROSPECTOR_CFG, INTROSPECTOR_FUNC_SIG, \
      INTROSPECTOR_FUNCTION_SOURCE, INTROSPECTOR_PROJECT_SOURCE, \
      INTROSPECTOR_XREF, INTROSPECTOR_TYPE, INTROSPECTOR_ORACLE_FAR_REACH, \
      INTROSPECTOR_ORACLE_KEYWORD, INTROSPECTOR_ADDR_TYPE, \
      INTROSPECTOR_ALL_HEADER_FILES, INTROSPECTOR_ALL_FUNC_TYPES, \
      INTROSPECTOR_SAMPLE_XREFS, INTROSPECTOR_ORACLE_EASY_PARAMS, \
      INTROSPECTOR_ORACLE_ALL_JVM_PUBLIC_CANDIDATES, \
      INTROSPECTOR_ALL_JVM_SOURCE_PATH, INTROSPECTOR_ORACLE_OPTIMAL, \
      INTROSPECTOR_HEADERS_FOR_FUNC, \
      INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE

  INTROSPECTOR_ENDPOINT = endpoint
  logging.info('Fuzz Introspector endpoint set to %s', INTROSPECTOR_ENDPOINT)

  INTROSPECTOR_CFG = f'{INTROSPECTOR_ENDPOINT}/annotated-cfg'
  INTROSPECTOR_ORACLE_FAR_REACH = (
      f'{INTROSPECTOR_ENDPOINT}/far-reach-but-low-coverage')
  INTROSPECTOR_ORACLE_KEYWORD = (
      f'{INTROSPECTOR_ENDPOINT}/far-reach-low-cov-fuzz-keyword')
  INTROSPECTOR_ORACLE_EASY_PARAMS = (
      f'{INTROSPECTOR_ENDPOINT}/easy-params-far-reach')
  INTROSPECTOR_ORACLE_ALL_JVM_PUBLIC_CANDIDATES = (
      f'{INTROSPECTOR_ENDPOINT}/all-public-candidates')
  INTROSPECTOR_ORACLE_OPTIMAL = f'{INTROSPECTOR_ENDPOINT}/optimal-targets'
  INTROSPECTOR_FUNCTION_SOURCE = f'{INTROSPECTOR_ENDPOINT}/function-source-code'
  INTROSPECTOR_PROJECT_SOURCE = f'{INTROSPECTOR_ENDPOINT}/project-source-code'
  INTROSPECTOR_XREF = f'{INTROSPECTOR_ENDPOINT}/all-cross-references'
  INTROSPECTOR_TYPE = f'{INTROSPECTOR_ENDPOINT}/type-info'
  INTROSPECTOR_FUNC_SIG = f'{INTROSPECTOR_ENDPOINT}/function-signature'
  INTROSPECTOR_ADDR_TYPE = (
      f'{INTROSPECTOR_ENDPOINT}/addr-to-recursive-dwarf-info')
  INTROSPECTOR_ALL_HEADER_FILES = f'{INTROSPECTOR_ENDPOINT}/all-header-files'
  INTROSPECTOR_ALL_FUNC_TYPES = f'{INTROSPECTOR_ENDPOINT}/func-debug-types'
  INTROSPECTOR_HEADERS_FOR_FUNC = (
      f'{INTROSPECTOR_ENDPOINT}/get-header-files-needed-for-function')
  INTROSPECTOR_SAMPLE_XREFS = (
      f'{INTROSPECTOR_ENDPOINT}/sample-cross-references')
  INTROSPECTOR_ALL_JVM_SOURCE_PATH = (
      f'{INTROSPECTOR_ENDPOINT}/all-project-source-files')
  INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE = (
      f'{INTROSPECTOR_ENDPOINT}/function-with-matching-return-type')


def _construct_url(api: str, params: dict) -> str:
  """Constructs an encoded url for the |api| with |params|."""
  return api + '?' + urlencode(params)


def _query_introspector(api: str, params: dict) -> Optional[requests.Response]:
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
      return resp
    except requests.exceptions.Timeout as err:
      if attempt_num == MAX_RETRY:
        logging.error(
            'Failed to get data from FI due to timeout, max retry exceeded:\n'
            '%s\n'
            'Error: %s', _construct_url(api, params), err)
        break
      delay = 5 * 2**attempt_num + random.randint(1, 10)
      logging.warning(
          'Failed to get data from FI due to timeout on attempt %d, '
          'retry in %ds...', attempt_num, delay)
      time.sleep(delay)
    except requests.exceptions.RequestException as err:
      logging.error(
          'Failed to get data from FI due to unexpected error:\n'
          '%s\n'
          'Error: %s', _construct_url(api, params), err)
      break

  return None


def _get_data(resp: Optional[requests.Response], key: str,
              default_value: T) -> T:
  """Gets the value specified by |key| from a Request |resp|."""
  if not resp:
    return default_value

  try:
    data = resp.json()
  except requests.exceptions.InvalidJSONError:
    logging.error(
        'Unable to parse response from FI:\n'
        '%s\n'
        '-----------Response received------------\n'
        '%s\n'
        '------------End of response-------------', resp.url,
        resp.content.decode('utf-8').strip())
    return default_value

  content = data.get(key)
  if content:
    return content

  logging.error('Failed to get %s from FI:\n'
                '%s\n'
                '%s', key, resp.url, data)
  return default_value


def query_introspector_oracle(project: str, oracle_api: str) -> list[dict]:
  """Queries a fuzz target oracle API from Fuzz Introspector."""
  resp = _query_introspector(
      oracle_api, {
          'project':
              project,
          'exclude-static-functions':
              ORACLE_AVOID_STATIC_FUNCTIONS,
          'only-referenced-functions':
              ORACLE_ONLY_REFERENCED_FUNCTIONS,
          'only-with-header-file-declaration':
              ORACLE_ONLY_FUNCTIONS_WITH_HEADER_DECLARATIONS,
      })
  return _get_data(resp, 'functions', [])


def query_introspector_for_optimal_targets(project: str) -> list[dict]:
  """Queries Fuzz Introspector for optimal target analysis."""
  return query_introspector_oracle(project, INTROSPECTOR_ORACLE_OPTIMAL)


def query_introspector_for_keyword_targets(project: str) -> list[dict]:
  """Queries FuzzIntrospector for targets with interesting fuzz keywords."""
  return query_introspector_oracle(project, INTROSPECTOR_ORACLE_KEYWORD)


def query_introspector_for_easy_param_targets(project: str) -> list[dict]:
  """Queries Fuzz Introspector for targets that have fuzzer-friendly params,
  such as data buffers."""
  return query_introspector_oracle(project, INTROSPECTOR_ORACLE_EASY_PARAMS)


def query_introspector_jvm_all_public_candidates(project: str) -> list[dict]:
  """Queries Fuzz Introspector for all public accessible function or
  constructor candidates.
  """
  return query_introspector_oracle(
      project, INTROSPECTOR_ORACLE_ALL_JVM_PUBLIC_CANDIDATES)


def query_introspector_for_targets(project, target_oracle) -> list[Dict]:
  """Queries introspector for target functions."""
  query_func = get_oracle_dict().get(target_oracle, None)
  if not query_func:
    logging.error('No such oracle "%s"', target_oracle)
    sys.exit(1)
  return query_func(project)


def query_introspector_cfg(project: str) -> dict:
  """Queries FuzzIntrospector API for CFG."""
  resp = _query_introspector(INTROSPECTOR_CFG, {'project': project})
  return _get_data(resp, 'project', {})


def query_introspector_source_file_path(project: str, func_sig: str) -> str:
  """Queries FuzzIntrospector API for file path of |func_sig|."""
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  return _get_data(resp, 'filepath', '')


def query_introspector_function_source(project: str, func_sig: str) -> str:
  """Queries FuzzIntrospector API for source code of |func_sig|."""
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  return _get_data(resp, 'source', '')


def query_introspector_function_line(project: str, func_sig: str) -> list:
  """Queries FuzzIntrospector API for source line of |func_sig|."""
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  return [_get_data(resp, 'src_begin', 0), _get_data(resp, 'src_end', 0)]


def query_introspector_source_code(project: str, filepath: str, begin_line: int,
                                   end_line: int) -> str:
  """Queries FuzzIntrospector API for source code of a
    file |filepath| between |begin_line| and |end_line|."""

  resp = _query_introspector(
      INTROSPECTOR_PROJECT_SOURCE, {
          'project': project,
          'filepath': filepath,
          'begin_line': begin_line,
          'end_line': end_line,
      })

  return _get_data(resp, 'source_code', '')


def query_introspector_header_files(project: str) -> List[str]:
  """Queries for the header files used in a given project."""
  resp = _query_introspector(INTROSPECTOR_ALL_HEADER_FILES,
                             {'project': project})
  all_header_files = _get_data(resp, 'all-header-files', [])
  return all_header_files


def query_introspector_sample_xrefs(project: str, func_sig: str) -> List[str]:
  """Queries for sample references in the form of source code."""
  resp = _query_introspector(INTROSPECTOR_SAMPLE_XREFS, {
      'project': project,
      'function_signature': func_sig
  })
  return _get_data(resp, 'source-code-refs', [])


def query_introspector_jvm_source_path(project: str) -> List[str]:
  """Queries for all java source paths of a given project."""
  resp = _query_introspector(INTROSPECTOR_ALL_JVM_SOURCE_PATH,
                             {'project': project})
  return _get_data(resp, 'src_path', [])


def query_introspector_matching_function_constructor_type(
    project: str, return_type: str, is_function: bool) -> List[Dict[str, Any]]:
  """Queries for all functions or all constructors that returns a given type
  in a given project."""
  simple_types_should_not_process = [
      'byte', 'char', 'boolean', 'short', 'long', 'int', 'float', 'double',
      'void', 'java.lang.String', 'java.lang.CharSequence'
  ]
  if return_type in simple_types_should_not_process:
    # Avoid querying introspector for simple object types as this API is
    # not meant to be used for creating simple object.
    return []

  resp = _query_introspector(INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE, {
      'project': project,
      'return_type': return_type
  })

  if is_function:
    return _get_data(resp, 'functions', [])

  return _get_data(resp, 'constructors', [])


def query_introspector_header_files_to_include(project: str,
                                               func_sig: str) -> List[str]:
  """Queries Fuzz Introspector header files where a function is likely
  declared."""
  resp = _query_introspector(INTROSPECTOR_HEADERS_FOR_FUNC, {
      'project': project,
      'function_signature': func_sig
  })
  arg_types = _get_data(resp, 'headers-to-include', [])
  return arg_types


def query_introspector_function_debug_arg_types(project: str,
                                                func_sig: str) -> List[str]:
  """Queries FuzzIntrospector function arguments extracted by way of debug
  info."""
  resp = _query_introspector(INTROSPECTOR_ALL_FUNC_TYPES, {
      'project': project,
      'function_signature': func_sig
  })
  arg_types = _get_data(resp, 'arg-types', [])
  return arg_types


def query_introspector_cross_references(project: str,
                                        func_sig: str) -> list[str]:
  """Queries FuzzIntrospector API for source code of functions
  which reference |func_sig|."""
  resp = _query_introspector(INTROSPECTOR_XREF, {
      'project': project,
      'function_signature': func_sig
  })
  call_sites = _get_data(resp, 'callsites', [])

  xref_source = []
  for cs in call_sites:
    name = cs.get('src_func')
    sig = query_introspector_function_signature(project, name)
    source = query_introspector_function_source(project, sig)
    xref_source.append(source)
  return xref_source


def query_introspector_type_info(project: str, type_name: str) -> list[dict]:
  """Queries FuzzIntrospector API for information of |type_name|."""
  resp = _query_introspector(INTROSPECTOR_TYPE, {
      'project': project,
      'name': type_name
  })
  return _get_data(resp, 'type_data', [])


def query_introspector_function_signature(project: str,
                                          function_name: str) -> str:
  """Queries FuzzIntrospector API for signature of |function_name|."""
  resp = _query_introspector(INTROSPECTOR_FUNC_SIG, {
      'project': project,
      'function': function_name
  })
  return _get_data(resp, 'signature', '')


def query_introspector_addr_type_info(project: str, addr: str) -> str:
  """Queries FuzzIntrospector API for type information for a type
  identified by its address used during compilation."""
  resp = _query_introspector(INTROSPECTOR_ADDR_TYPE, {
      'project': project,
      'addr': addr
  })

  return _get_data(resp, 'dwarf-map', '')


def get_unreached_functions(project):
  functions = query_introspector_oracle(project, INTROSPECTOR_ORACLE_FAR_REACH)
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


def _get_arg_count(function: dict) -> int:
  """Count the number of arguments for this function."""
  raw_arg_types = (function.get('arg-types') or
                   function.get('function_arguments', []))
  return len(raw_arg_types)


def _get_exceptions(function: dict) -> List[str]:
  """Returns the exception list of this function."""
  return function.get('exceptions', [])


def _get_arg_names(function: dict, project: str, language: str) -> list[str]:
  """Returns the function argument names."""
  if language == 'jvm':
    # The fuzz-introspector front end of JVM projects cannot get the original
    # argument name. Thus the argument name here uses arg{Count} as arugment
    # name reference.
    jvm_args = _get_clean_arg_types(function, project)
    arg_names = [f'arg{i}' for i in range(len(jvm_args))]
  else:
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
  if function_signature == "N/A":
    # For JVM projects, the full function signature are the raw function name
    return get_raw_function_name(function, project)
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


def _select_top_functions_from_oracle(project: str, limit: int,
                                      target_oracle: str,
                                      target_oracles: list[str]) -> OrderedDict:
  """Selects the top |limit| functions from |target_oracle|."""
  if target_oracle not in target_oracles:
    return OrderedDict()

  logging.info('Extracting functions using oracle %s.', target_oracle)
  functions = query_introspector_for_targets(project, target_oracle)[:limit]

  return OrderedDict((func['function_signature'], func) for func in functions)


def _combine_functions(a: list[str], b: list[str], c: list[str],
                       limit: int) -> list[str]:
  """Combines functions from three oracles. Prioritize on a, but include one of
  b and c if any."""
  head = a[:limit - 2]
  b_in_head = any(i in b for i in head)
  c_in_head = any(i in c for i in head)
  # Result contains items from b and c and is long enough.
  if b_in_head and c_in_head and len(a) >= limit:
    return a

  all_functions = a + b + c

  if b_in_head or not b:
    add_from_b = []
  else:
    add_from_b = [i for i in a[3:] if i in b]
    add_from_b = [add_from_b[0]] if add_from_b else [b[0]]

  if c_in_head or not c:
    add_from_c = []
  else:
    add_from_c = [i for i in a[3:] if i in c]
    add_from_c = [add_from_c[0]] if add_from_c else [c[0]]

  combined = set(head + add_from_b + add_from_c)
  # Result contains items from b and c, append more until long enough.
  for func in all_functions:
    if len(combined) >= limit:
      continue
    combined.add(func)
  return list(combined)


def _select_functions_from_oracles(project: str, limit: int,
                                   target_oracles: List[str]) -> list[dict]:
  """Selects function-under-test from oracles."""
  all_functions = OrderedDict()
  frlc_targets = _select_top_functions_from_oracle(project, limit,
                                                   'far-reach-low-coverage',
                                                   target_oracles)
  # FRLC is the primary oracle. If it does not exist, follow oracle order and
  # deduplicate.
  if not frlc_targets:
    for target_oracle in target_oracles:
      tmp_functions = _select_top_functions_from_oracle(project, limit,
                                                        target_oracle,
                                                        target_oracles)
      all_functions.update(tmp_functions)
      return list(all_functions.values())[:limit]

  # Selection rule: Prioritize on far-reach-low-coverage, but include one of
  # optimal-targets, easy-params-far-reach if any.
  all_functions.update(frlc_targets)

  epfr_targets = _select_top_functions_from_oracle(project, limit,
                                                   'easy-params-far-reach',
                                                   target_oracles)
  all_functions.update(epfr_targets)

  ot_targets = _select_top_functions_from_oracle(project, limit,
                                                 'optimal-targets',
                                                 target_oracles)
  all_functions.update(ot_targets)

  selected_singatures = _combine_functions(list(frlc_targets.keys()),
                                           list(epfr_targets.keys()),
                                           list(ot_targets.keys()), limit)

  return [all_functions[func] for func in selected_singatures]


def populate_benchmarks_using_introspector(project: str, language: str,
                                           limit: int,
                                           target_oracles: List[str]):
  """Populates benchmark YAML files from the data from FuzzIntrospector."""
  functions = _select_functions_from_oracles(project, limit, target_oracles)

  if not functions:
    logging.error('No functions found using the oracles: %s', target_oracles)
    return []

  if language == 'jvm':
    filenames = [
        f'{function["function_filename"].split("$")[0].replace(".", "/")}.java'
        for function in functions
    ]
  else:
    filenames = [
        os.path.basename(function['function_filename'])
        for function in functions
    ]

  result = project_src.search_source(project, filenames, language)
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
    if _get_arg_count(function) == 0:
      # Skipping functions / methods that does not take in any arguments.
      # Those functions / methods are not fuzz-worthy.
      continue

    filename = os.path.basename(function['function_filename'])

    if language == 'jvm':
      # Retrieve list of source file from introspector
      src_path_list = query_introspector_jvm_source_path(project)
      if src_path_list:
        # For all JVM projects, the full class name is stored in the filename
        # field. The full class name includes the package of the class and that
        # forms part of the directory pattern of the source file that is needed
        # for checking. For example, the source file of class a.b.c.d is always
        # stored as <SOURCE_BASE>/a/b/c/d.java
        src_file = f'{filename.replace(".", "/")}.java'
        if src_file not in src_path_list:
          logging.error('error: %s %s', filename, interesting.keys())
          continue
    elif filename not in [os.path.basename(i) for i in interesting.keys()]:
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
                                   _get_arg_names(function, project, language)),
                               _get_exceptions(function),
                               harness,
                               target_name,
                               function_dict=function))

    if len(potential_benchmarks) >= (limit * len(target_oracles)):
      break
  print("Length of potential targets: %d" % (len(potential_benchmarks)))

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
    logging.error('No fuzz introspector report is found.')
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


def _parse_arguments() -> argparse.Namespace:
  """Parses command line args."""
  parser = argparse.ArgumentParser(
      description='Parse arguments to generate benchmarks.')

  parser.add_argument('project', help='Name of the project.', type=str)
  parser.add_argument('-m',
                      '--max-functions',
                      type=int,
                      default=3,
                      help='Number of benchmarks to generate.')
  parser.add_argument('-o',
                      '--out',
                      type=str,
                      default='',
                      help='Output directory.')
  parser.add_argument('-e',
                      '--endpoint',
                      type=str,
                      default=DEFAULT_INTROSPECTOR_ENDPOINT,
                      help='Fuzz Introspecor API endpoint.')
  parser.add_argument('-t',
                      '--target-oracle',
                      type=str,
                      nargs='+',
                      default=['optimal-targets', 'far-reach-low-coverage'],
                      help='Oracles used to determine interesting targets.')

  return parser.parse_args()


# Set default endpoint.
set_introspector_endpoints(DEFAULT_INTROSPECTOR_ENDPOINT)

if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)

  args = _parse_arguments()
  if args.out:
    os.makedirs(args.out, exist_ok=True)

  set_introspector_endpoints(args.endpoint)

  try:
    oss_fuzz_checkout.clone_oss_fuzz()
    oss_fuzz_checkout.postprocess_oss_fuzz()
  except subprocess.CalledProcessError as e:
    logging.error('Failed to prepare OSS-Fuzz directory for project %s: %s',
                  args.project, e)
  cur_project_language = oss_fuzz_checkout.get_project_language(args.project)
  benchmarks = populate_benchmarks_using_introspector(args.project,
                                                      cur_project_language,
                                                      args.max_functions,
                                                      args.target_oracle)
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, args.out)
  else:
    logging.error('Nothing found for %s', args.project)
    sys.exit(1)
