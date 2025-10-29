#!/usr/bin/env python3
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

logger = logging.getLogger(__name__)

T = TypeVar('T', str, list, dict, int)  # Generic type.

TIMEOUT = 45
MAX_RETRY = 5

BENCHMARK_ROOT: str = './conti-benchmark'
BENCHMARK_DIR: str = f'{BENCHMARK_ROOT}/conti-cmp'
GENERATED_BENCHMARK: str = 'generated-benchmark-'

USE_FI_TO_GET_TARGETS = bool(int(os.getenv('OSS_FI_TO_GET_TARGETS', '1')))

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
INTROSPECTOR_ORACLE_ALL_PUBLIC_CANDIDATES = ''
INTROSPECTOR_ORACLE_OPTIMAL = ''
INTROSPECTOR_ORACLE_ALL_TESTS = ''
INTROSPECTOR_ORACLE_ALL_TESTS_XREF = ''
INTROSPECTOR_FUNCTION_SOURCE = ''
INTROSPECTOR_PROJECT_SOURCE = ''
INTROSPECTOR_XREF = ''
INTROSPECTOR_FUNC_SIG = ''
INTROSPECTOR_ADDR_TYPE = ''
INTROSPECTOR_ALL_HEADER_FILES = ''
INTROSPECTOR_ALL_FUNC_TYPES = ''
INTROSPECTOR_ALL_TYPE_DEFINITION = ''
INTROSPECTOR_TEST_SOURCE = ''
INTROSPECTOR_HARNESS_SOURCE_AND_EXEC = ''
INTROSPECTOR_LANGUAGE_STATS = ''
INTROSPECTOR_GET_TARGET_FUNCTION = ''
INTROSPECTOR_CHECK_MACRO = ''
INTROSPECTOR_ALL_FUNCTIONS = ''

INTROSPECTOR_HEADERS_FOR_FUNC = ''
INTROSPECTOR_SAMPLE_XREFS = ''
INTROSPECTOR_ALL_JVM_SOURCE_PATH = ''
INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE = ''
INTROSPECTOR_JVM_PROPERTIES = ''
INTROSPECTOR_JVM_PUBLIC_CLASSES = ''

def get_oracle_dict() -> Dict[str, Any]:
  """Returns the oracles available to identify targets."""
  # Do this in a function to allow for forward-declaration of functions below.
  oracle_dict = {
      'far-reach-low-coverage': query_introspector_for_far_reach_low_cov,
      'low-cov-with-fuzz-keyword': query_introspector_for_keyword_targets,
      'easy-params-far-reach': query_introspector_for_easy_param_targets,
      'optimal-targets': query_introspector_for_optimal_targets,
      'test-migration': query_introspector_for_tests,
      'all-public-candidates': query_introspector_all_public_candidates,
  }
  return oracle_dict

def set_introspector_endpoints(endpoint):
  """Sets URLs for Fuzz Introspector endpoints to local or remote endpoints."""
  global INTROSPECTOR_ENDPOINT, INTROSPECTOR_CFG, INTROSPECTOR_FUNC_SIG, \
      INTROSPECTOR_FUNCTION_SOURCE, INTROSPECTOR_PROJECT_SOURCE, \
      INTROSPECTOR_XREF, INTROSPECTOR_ORACLE_FAR_REACH, \
      INTROSPECTOR_ORACLE_KEYWORD, INTROSPECTOR_ADDR_TYPE, \
      INTROSPECTOR_ALL_HEADER_FILES, INTROSPECTOR_ALL_FUNC_TYPES, \
      INTROSPECTOR_SAMPLE_XREFS, INTROSPECTOR_ORACLE_EASY_PARAMS, \
      INTROSPECTOR_ORACLE_ALL_PUBLIC_CANDIDATES, \
      INTROSPECTOR_ALL_JVM_SOURCE_PATH, INTROSPECTOR_ORACLE_OPTIMAL, \
      INTROSPECTOR_HEADERS_FOR_FUNC, \
      INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE, \
      INTROSPECTOR_ORACLE_ALL_TESTS, INTROSPECTOR_JVM_PROPERTIES, \
      INTROSPECTOR_TEST_SOURCE, INTROSPECTOR_HARNESS_SOURCE_AND_EXEC, \
      INTROSPECTOR_JVM_PUBLIC_CLASSES, INTROSPECTOR_LANGUAGE_STATS, \
      INTROSPECTOR_GET_TARGET_FUNCTION, INTROSPECTOR_ALL_TYPE_DEFINITION, \
      INTROSPECTOR_CHECK_MACRO, INTROSPECTOR_ORACLE_ALL_TESTS_XREF, \
      INTROSPECTOR_ALL_FUNCTIONS

  INTROSPECTOR_ENDPOINT = endpoint

  INTROSPECTOR_CFG = f'{INTROSPECTOR_ENDPOINT}/annotated-cfg'
  INTROSPECTOR_ORACLE_FAR_REACH = (
      f'{INTROSPECTOR_ENDPOINT}/far-reach-but-low-coverage')
  INTROSPECTOR_ORACLE_KEYWORD = (
      f'{INTROSPECTOR_ENDPOINT}/far-reach-low-cov-fuzz-keyword')
  INTROSPECTOR_ORACLE_EASY_PARAMS = (
      f'{INTROSPECTOR_ENDPOINT}/easy-params-far-reach')
  INTROSPECTOR_ORACLE_ALL_PUBLIC_CANDIDATES = (
      f'{INTROSPECTOR_ENDPOINT}/all-public-candidates')
  INTROSPECTOR_ORACLE_OPTIMAL = f'{INTROSPECTOR_ENDPOINT}/optimal-targets'
  INTROSPECTOR_FUNCTION_SOURCE = f'{INTROSPECTOR_ENDPOINT}/function-source-code'
  INTROSPECTOR_PROJECT_SOURCE = f'{INTROSPECTOR_ENDPOINT}/project-source-code'
  INTROSPECTOR_TEST_SOURCE = f'{INTROSPECTOR_ENDPOINT}/project-test-code'
  INTROSPECTOR_XREF = f'{INTROSPECTOR_ENDPOINT}/all-cross-references'
  INTROSPECTOR_FUNC_SIG = f'{INTROSPECTOR_ENDPOINT}/function-signature'
  INTROSPECTOR_ADDR_TYPE = (
      f'{INTROSPECTOR_ENDPOINT}/addr-to-recursive-dwarf-info')
  INTROSPECTOR_ALL_HEADER_FILES = f'{INTROSPECTOR_ENDPOINT}/all-header-files'
  INTROSPECTOR_ALL_FUNC_TYPES = f'{INTROSPECTOR_ENDPOINT}/func-debug-types'
  INTROSPECTOR_ALL_TYPE_DEFINITION = (
      f'{INTROSPECTOR_ENDPOINT}/full-type-definition')
  INTROSPECTOR_HEADERS_FOR_FUNC = (
      f'{INTROSPECTOR_ENDPOINT}/get-header-files-needed-for-function')
  INTROSPECTOR_SAMPLE_XREFS = (
      f'{INTROSPECTOR_ENDPOINT}/sample-cross-references')
  INTROSPECTOR_ALL_JVM_SOURCE_PATH = (
      f'{INTROSPECTOR_ENDPOINT}/all-project-source-files')
  INTROSPECTOR_FUNCTION_WITH_MATCHING_RETURN_TYPE = (
      f'{INTROSPECTOR_ENDPOINT}/function-with-matching-return-type')
  INTROSPECTOR_ORACLE_ALL_TESTS = f'{INTROSPECTOR_ENDPOINT}/project-tests'
  INTROSPECTOR_ORACLE_ALL_TESTS_XREF = (
      f'{INTROSPECTOR_ENDPOINT}/project-tests-for-functions')
  INTROSPECTOR_JVM_PROPERTIES = f'{INTROSPECTOR_ENDPOINT}/jvm-method-properties'
  INTROSPECTOR_HARNESS_SOURCE_AND_EXEC = (
      f'{INTROSPECTOR_ENDPOINT}/harness-source-and-executable')
  INTROSPECTOR_JVM_PUBLIC_CLASSES = (
      f'{INTROSPECTOR_ENDPOINT}/all-public-classes')
  INTROSPECTOR_LANGUAGE_STATS = (
      f'{INTROSPECTOR_ENDPOINT}/database-language-stats')
  INTROSPECTOR_GET_TARGET_FUNCTION = (
      f'{INTROSPECTOR_ENDPOINT}/get-target-function')
  INTROSPECTOR_GET_ALL_FUNCTIONS = f'{INTROSPECTOR_ENDPOINT}/all-functions'
  INTROSPECTOR_CHECK_MACRO = f'{INTROSPECTOR_ENDPOINT}/check_macro'
  INTROSPECTOR_ALL_FUNCTIONS = f'{INTROSPECTOR_ENDPOINT}/all-functions'

def _construct_url(api: str, params: dict) -> str:
  """Constructs an encoded url for the |api| with |params|."""
  return api + '?' + urlencode(params)

def _query_introspector(api: str, params: dict) -> Optional[requests.Response]:
  """Queries FuzzIntrospector API and returns the json payload,
  returns an empty dict if unable to get data."""

  logger.info('Querying FuzzIntrospector API: %s\n', api)
  for attempt_num in range(1, MAX_RETRY + 1):
    try:
      resp = requests.get(api, params, timeout=TIMEOUT)
      if not resp.ok:
        logger.error(
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
        logger.error(
            'Failed to get data from FI due to timeout, max retry exceeded:\n'
            '%s\n'
            'Error: %s', _construct_url(api, params), err)
        break
      delay = 5 * 2**attempt_num + random.randint(1, 10)
      logger.warning(
          'Failed to get data from FI due to timeout on attempt %d:\n'
          '%s\n'
          'retry in %ds...', attempt_num, _construct_url(api, params), delay)
      time.sleep(delay)
    except requests.exceptions.RequestException as err:
      logger.error(
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
    logger.error(
        'Unable to parse response from FI:\n'
        '%s\n'
        '-----------Response received------------\n'
        '%s\n'
        '------------End of response-------------', resp.url,
        resp.content.decode('utf-8').strip())
    return default_value

  # To handle the case that some FI query could return empty list,
  # empty dict or boolean value False
  content = data.get(key)
  if content or key in data.keys():
    return content

  logger.error('Failed to get %s from FI:\n'
               '%s\n'
               '%s', key, resp.url, data)
  return default_value

def query_introspector_for_tests(project: str) -> list[str]:
  """Gets the list of test files in the target project."""
  resp = _query_introspector(INTROSPECTOR_ORACLE_ALL_TESTS, {
      'project': project,
  })
  return _get_data(resp, 'test-file-list', [])

def query_introspector_for_tests_xref(
    project: str, functions: Optional[list[str]]) -> dict[str, list[Any]]:
  """Gets the list of functions and xref test files in the target project."""
  data = {'project': project}
  if functions:
    demangled = [demangle(function).split('(')[0] for function in functions]
    data['functions'] = ','.join(demangled)

  resp = _query_introspector(INTROSPECTOR_ORACLE_ALL_TESTS_XREF, data)

  details = _get_data(resp, 'details', False)
  test_files = _get_data(resp, 'test-files-xref', {})

  handled = set()
  result_list = []
  detail_list = []
  key_list = test_files.keys()
  for test_paths in test_files.values():
    # Only dump the details from the test source files
    # which are related to the target function calls
    if details and isinstance(test_paths, dict):
      for test_path, calls in test_paths.items():
        source_code = query_introspector_test_source(project, test_path)
        lines = source_code.splitlines()

        # Include details of function calls in test files
        for call in calls:
          result_lines = []
          start = call.get('call_start', -1)
          end = call.get('call_end', -1)
          params = call.get('params')

          # Skip invalid data
          if start <= 0 or end <= 0 or params is None:
            continue

          call_lines = lines[start - 1:end]

          param_list = []
          for param in params:
            param_dict = {}

            decl = param.get('decl_line', -1)
            start = param.get('init_start', -1)
            end = param.get('init_end', -1)
            func = param.get('init_func')

            # Skip invalid data
            if decl <= 0 or decl >= len(lines):
              continue

            result_lines.append(lines[decl - 1])
            if func and start > 0 and end > 0:
              result_lines.extend(lines[start - 1:end])

          result_lines.extend(call_lines)

          detail_list.append(result_lines)

      continue

    # Plain dump of test source files with limited number
    # of result lines if details not found
    for test_path in test_paths:
      if len(result_list) > 100:
        break

      if test_path in handled:
        continue

      handled.add(test_path)
      source_code = query_introspector_test_source(project, test_path)
      lines = source_code.splitlines()

      # Retrieve needed line range in the source file
      target_lines = list()
      for idx, line in enumerate(lines):
        if any(func.split('::')[-1] in line for func in key_list):
          target_lines.append((max(0, idx - 20), min(len(lines), idx + 20)))

      # Fail safe
      if not target_lines:
        continue

      # Merging line range
      ranges = [target_lines[0]]
      for start, end in target_lines[1:]:
        last_start, last_end = ranges[-1]
        if start <= last_end + 1:
          # Merge range
          ranges[-1] = (last_start, max(last_end, end))
        else:
          ranges.append((start, end))

      # Extract source code lines in needed range
      for start, end in ranges:
        result_list.extend(lines[start:end])

  result_dict = {}
  result_dict['source'] = result_list
  result_dict['details'] = detail_list
  return result_dict

def query_introspector_for_harness_intrinsics(
    project: str) -> list[dict[str, str]]:
  """Gets the list of test files in the target project."""
  resp = _query_introspector(INTROSPECTOR_HARNESS_SOURCE_AND_EXEC, {
      'project': project,
  })
  return _get_data(resp, 'pairs', [])

def query_introspector_all_functions(project: str) -> list[dict]:
  """Queries FuzzIntrospector API for all functions in a project."""
  resp = _query_introspector(INTROSPECTOR_ALL_FUNCTIONS, {
      'project': project,
  })
  return _get_data(resp, 'functions', [])

def query_introspector_all_signatures(project: str) -> list[str]:
  """Queries FuzzIntrospector API for all functions in a project."""
  functions: list[dict] = query_introspector_all_functions(project)
  new_funcs = []
  for func in functions:
    new_funcs.append(func['function_signature'])
  return new_funcs

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

def query_introspector_all_public_candidates(project: str) -> list[dict]:
  """Queries Fuzz Introspector for all public accessible function or
  constructor candidates.
  """
  return query_introspector_oracle(project,
                                   INTROSPECTOR_ORACLE_ALL_PUBLIC_CANDIDATES)

def query_introspector_for_targets(project, target_oracle) -> list[Dict]:
  """Queries introspector for target functions."""
  query_func = get_oracle_dict().get(target_oracle, None)
  if not query_func:
    logger.error('No such oracle "%s"', target_oracle)
    sys.exit(1)
  return query_func(project)

def _extract_function_name_from_signature(func_sig: str) -> str:
  """Extracts the function name from a function signature.
  
  Args:
      func_sig: Function signature like "void LibRaw::crxLoadDecodeLoop(void *, int)"
  
  Returns:
      Function name like "LibRaw::crxLoadDecodeLoop", or empty string if extraction fails.
  """
  import re
  # Match pattern: [return_type] [namespace::]*function_name(params)
  match = re.search(r'[\w:]+\([^)]*\)', func_sig)
  if match:
    func_name_with_params = match.group(0)
    func_name = func_name_with_params.split('(')[0]
    return func_name
  return ''

def query_introspector_cfg(project: str) -> dict:
  """Queries FuzzIntrospector API for CFG."""
  resp = _query_introspector(INTROSPECTOR_CFG, {'project': project})
  return _get_data(resp, 'project', {})

def query_introspector_source_file_path(project: str, func_sig: str) -> str:
  """Queries FuzzIntrospector API for file path of |func_sig|.
  
  If the query fails with the provided signature, this function will attempt
  to resolve the full signature from FuzzIntrospector and retry.
  """
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  filepath = _get_data(resp, 'filepath', '')
  
  # If query failed, try to get the full signature from FuzzIntrospector
  if not filepath:
    logger.info('Failed to query filepath with signature: %s. Attempting to resolve full signature.', func_sig)
    
    func_name = _extract_function_name_from_signature(func_sig)
    if func_name:
      logger.info('Extracted function name: %s. Querying for full signature.', func_name)
      full_sig = query_introspector_function_signature(project, func_name)
      
      if full_sig and full_sig != func_sig:
        logger.info('Found full signature: %s. Retrying query.', full_sig)
        resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
            'project': project,
            'function_signature': full_sig
        })
        filepath = _get_data(resp, 'filepath', '')
  
  return filepath

def query_introspector_function_source(project: str, func_sig: str) -> str:
  """Queries FuzzIntrospector API for source code of |func_sig|.
  
  If the query fails with the provided signature, this function will attempt
  to resolve the full signature from FuzzIntrospector and retry.
  """
  # Don't query if signature is empty
  if not func_sig or not func_sig.strip():
    logger.error('Cannot query function source: empty function signature provided')
    return ''
  
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  source = _get_data(resp, 'source', '')
  
  # If query failed, try to get the full signature from FuzzIntrospector
  if not source:
    logger.info('Failed to query with signature: %s. Attempting to resolve full signature.', func_sig)
    
    func_name = _extract_function_name_from_signature(func_sig)
    if func_name:
      logger.info('Extracted function name: %s. Querying for full signature.', func_name)
      full_sig = query_introspector_function_signature(project, func_name)
      
      if full_sig and full_sig != func_sig:
        logger.info('Found full signature: %s. Retrying query.', full_sig)
        resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
            'project': project,
            'function_signature': full_sig
        })
        source = _get_data(resp, 'source', '')
      elif not full_sig:
        logger.warning('Could not resolve full signature for function: %s', func_name)
  
  return source

def query_introspector_function_line(project: str, func_sig: str) -> list:
  """Queries FuzzIntrospector API for source line of |func_sig|.
  
  If the query fails with the provided signature, this function will attempt
  to resolve the full signature from FuzzIntrospector and retry.
  """
  resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
      'project': project,
      'function_signature': func_sig
  })
  src_begin = _get_data(resp, 'src_begin', 0)
  src_end = _get_data(resp, 'src_end', 0)
  
  # If query failed, try to get the full signature from FuzzIntrospector
  if not src_begin and not src_end:
    logger.info('Failed to query line info with signature: %s. Attempting to resolve full signature.', func_sig)
    
    func_name = _extract_function_name_from_signature(func_sig)
    if func_name:
      logger.info('Extracted function name: %s. Querying for full signature.', func_name)
      full_sig = query_introspector_function_signature(project, func_name)
      
      if full_sig and full_sig != func_sig:
        logger.info('Found full signature: %s. Retrying query.', full_sig)
        resp = _query_introspector(INTROSPECTOR_FUNCTION_SOURCE, {
            'project': project,
            'function_signature': full_sig
        })
        src_begin = _get_data(resp, 'src_begin', 0)
        src_end = _get_data(resp, 'src_end', 0)
  
  return [src_begin, src_end]

def query_introspector_function_props(project: str, func_sig: str) -> dict:
  """Queries FuzzIntrospector API for additional properties of |func_sig|."""
  resp = _query_introspector(INTROSPECTOR_JVM_PROPERTIES, {
      'project': project,
      'function_signature': func_sig
  })
  return {
      'exceptions': _get_data(resp, 'exceptions', []),
      'is-jvm-static': _get_data(resp, 'is-jvm-static', False),
      'need-close': _get_data(resp, 'need-close', False)
  }

def query_introspector_public_classes(project: str) -> list[str]:
  """Queries FuzzIntrospector API for all public classes of |project|."""
  resp = _query_introspector(INTROSPECTOR_JVM_PUBLIC_CLASSES,
                             {'project': project})
  return _get_data(resp, 'classes', [])

def query_introspector_source_code(project: str,
                                   filepath: str,
                                   begin_line: int = 0,
                                   end_line: int = 10000) -> str:
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

def query_introspector_test_source(project: str, filepath: str) -> str:
  """Queries the source code of a test file from."""
  resp = _query_introspector(INTROSPECTOR_TEST_SOURCE, {
      'project': project,
      'filepath': filepath
  })
  return _get_data(resp, 'source_code', '')

def query_introspector_header_files(project: str) -> List[str]:
  """Queries for the header files used in a given project."""
  resp = _query_introspector(INTROSPECTOR_ALL_HEADER_FILES,
                             {'project': project})
  all_header_files = _get_data(resp, 'all-header-files', [])
  return all_header_files

def query_introspector_sample_xrefs(project: str, func_sig: str) -> List[str]:
  """Queries for sample references in the form of source code.
  
  If the query fails with the provided signature, this function will attempt
  to resolve the full signature from FuzzIntrospector and retry.
  """
  # Don't query if signature is empty
  if not func_sig or not func_sig.strip():
    logger.warning('Cannot query cross-references: empty function signature provided')
    return []
  
  resp = _query_introspector(INTROSPECTOR_SAMPLE_XREFS, {
      'project': project,
      'function_signature': func_sig
  })
  refs = _get_data(resp, 'source-code-refs', [])
  
  # If query failed, try to get the full signature from FuzzIntrospector
  if not refs:
    logger.info('Failed to query xrefs with signature: %s. Attempting to resolve full signature.', func_sig)
    
    func_name = _extract_function_name_from_signature(func_sig)
    if func_name:
      logger.info('Extracted function name: %s. Querying for full signature.', func_name)
      full_sig = query_introspector_function_signature(project, func_name)
      
      if full_sig and full_sig != func_sig:
        logger.info('Found full signature: %s. Retrying query.', full_sig)
        resp = _query_introspector(INTROSPECTOR_SAMPLE_XREFS, {
            'project': project,
            'function_signature': full_sig
        })
        refs = _get_data(resp, 'source-code-refs', [])
      elif not full_sig:
        logger.warning('Could not resolve full signature for function: %s', func_name)
  
  return refs

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
      'return-type': return_type
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

def query_introspector_type_definition(project: str) -> List[dict]:
  """Queries FuzzIntrospector for a full list of custom type definition
  including, union, struct, typedef, enum and macro definition."""
  resp = _query_introspector(INTROSPECTOR_ALL_TYPE_DEFINITION, {
      'project': project,
  })
  result = _get_data(resp, 'project', {})
  return result.get('typedef_list', [])

def query_introspector_macro_block(project: str,
                                   source_path: str,
                                   line_start: int = 0,
                                   line_end: int = 99999) -> List[dict]:
  """Queries FuzzIntrospector for a full list of custom type definition
  including, union, struct, typedef, enum and macro definition."""
  resp = _query_introspector(
      INTROSPECTOR_CHECK_MACRO, {
          'project': project,
          'source': source_path,
          'start': line_start,
          'end': line_end
      })
  result = _get_data(resp, 'project', {})
  return result.get('macro_block_info', [])

def query_introspector_call_sites_metadata(project: str,
                                            func_sig: str) -> list[dict]:
  """Queries FuzzIntrospector API for call site metadata without fetching full source code.
  
  This is more efficient than query_introspector_cross_references when you only need
  metadata about where a function is called, not the full source code of caller functions.
  
  Args:
    project: Project name
    func_sig: Function signature to query
    
  Returns:
    List of call site metadata dictionaries with keys:
    - src_func: Name of the calling function
    - src_file: Source file path (if available)
    - src_line: Line number where the call occurs (if available)
  """
  # Don't query if signature is empty
  if not func_sig or not func_sig.strip():
    logger.warning('Cannot query call sites: empty function signature provided')
    return []
  
  resp = _query_introspector(INTROSPECTOR_XREF, {
      'project': project,
      'function_signature': func_sig
  })
  call_sites = _get_data(resp, 'callsites', [])
  
  # Return the raw call site metadata
  return call_sites


def query_introspector_cross_references(project: str,
                                        func_sig: str) -> list[str]:
  """Queries FuzzIntrospector API for source code of functions
  which reference |func_sig|."""
  # Don't query if signature is empty
  if not func_sig or not func_sig.strip():
    logger.warning('Cannot query cross-references: empty function signature provided')
    return []
  
  # Use the new metadata function
  call_sites = query_introspector_call_sites_metadata(project, func_sig)

  xref_source = []
  for cs in call_sites:
    name = cs.get('src_func')
    if not name:
      continue
    
    sig = query_introspector_function_signature(project, name)
    if not sig:
      # Skip if we can't get the signature
      logger.debug('Skipping cross-reference %s: could not get signature', name)
      continue
    
    source = query_introspector_function_source(project, sig)
    if source:  # Only append non-empty sources
      xref_source.append(source)
  
  return xref_source

def query_introspector_language_stats() -> dict:
  """Queries introspector for language stats"""

  resp = _query_introspector(INTROSPECTOR_LANGUAGE_STATS, {})
  return _get_data(resp, 'stats', {})

def query_introspector_function_signature(project: str,
                                          function_name: str) -> str:
  """Queries FuzzIntrospector API for signature of |function_name|."""
  if not function_name or not function_name.strip():
    logger.error('Cannot query function signature: empty function name provided')
    return ''
  
  resp = _query_introspector(INTROSPECTOR_FUNC_SIG, {
      'project': project,
      'function': function_name
  })
  signature = _get_data(resp, 'signature', '')
  
  if not signature:
    logger.warning('Could not find signature for function: %s in project: %s', function_name, project)
  
  return signature

def query_introspector_addr_type_info(project: str, addr: str) -> str:
  """Queries FuzzIntrospector API for type information for a type
  identified by its address used during compilation."""
  resp = _query_introspector(INTROSPECTOR_ADDR_TYPE, {
      'project': project,
      'addr': addr
  })

  return _get_data(resp, 'dwarf-map', '')

def get_next_generated_benchmarks_dir() -> str:
  """Retuns the next folder to be used for generated benchmarks."""
  max_idx = -1
  # When generating benchmarks dynamically sometimes we may not have a
  # benchmark folder, as the command will be run from an arbitrary directory.
  # Create the benchmark folder if this is the case.
  if not os.path.isdir(BENCHMARK_ROOT):
    os.makedirs(BENCHMARK_ROOT)
  for benchmark_folder in os.listdir(BENCHMARK_ROOT):
    try:
      max_idx = max(max_idx,
                    int(benchmark_folder.replace(GENERATED_BENCHMARK, '')))
    except (ValueError, TypeError) as _:
      pass
  max_idx += 1
  return os.path.join(BENCHMARK_ROOT, f'{GENERATED_BENCHMARK}{max_idx}')

def query_introspector_target_function(project: str, function: str) -> dict:
  resp = _query_introspector(INTROSPECTOR_GET_TARGET_FUNCTION, {
      'project': project,
      'function': function
  })

  return _get_data(resp, 'function', {})

def query_introspector_for_far_reach_low_cov(project):
  functions = query_introspector_oracle(project, INTROSPECTOR_ORACLE_FAR_REACH)
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
    logger.error(
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
    logger.error('No raw function name in project: %s for function: %s',
                 project, function)
  return raw_name

def _get_clean_arg_types(function: dict, project: str) -> list[str]:
  """Returns the cleaned function argument types."""
  raw_arg_types = (function.get('arg-types') or
                   function.get('function_arguments', []))
  if not raw_arg_types:
    logger.error(
        'Missing argument types in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return [clean_type(arg_type) for arg_type in raw_arg_types]

def _get_arg_count(function: dict) -> int:
  """Count the number of arguments for this function."""
  raw_arg_types = (function.get('arg-types') or
                   function.get('function_arguments', []))
  return len(raw_arg_types)

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
    logger.error(
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
    logger.error(
        'Missing function signature in project: %s\n'
        '  raw_function_name: %s', project,
        get_raw_function_name(function, project))
  return function_signature

# TODO(dongge): Remove this function when FI fixes it.
def _parse_type_from_raw_tagged_type(tagged_type: str, language: str) -> str:
  """Returns type name from |tagged_type| such as struct.TypeA"""
  # Assume: Types do not contain dot(.).
  # (ascchan): This assumption is wrong on Java projects because
  # most full qulified classes name of Java projects have dot(.) to
  # identify the package name of the classes. Thus for Java projects,
  # this action needed to be skipped until this function is removed.
  if language == 'jvm':
    return tagged_type
  return tagged_type.split('.')[-1]

def _group_function_params(param_types: list[str], param_names: list[str],
                           language: str) -> list[dict[str, str]]:
  """Groups the type and name of each parameter."""
  return [{
      'type': _parse_type_from_raw_tagged_type(param_type, language),
      'name': param_name
  } for param_type, param_name in zip(param_types, param_names)]

def _select_top_functions_from_oracle(project: str, limit: int,
                                      target_oracle: str,
                                      target_oracles: list[str]) -> OrderedDict:
  """Selects the top |limit| functions from |target_oracle|."""
  if target_oracle not in target_oracles or target_oracle == 'test-migration':
    return OrderedDict()

  logger.info('Extracting functions using oracle %s.', target_oracle)
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

def _select_functions_from_jvm_oracles(project: str, limit: int,
                                       target_oracles: list[str]) -> list[dict]:
  """Selects functions from oracles designated for jvm projects, with
  jvm-public-candidates as the prioritised oracle"""
  all_functions = OrderedDict()

  if 'jvm-public-candidates' in target_oracles:
    # JPC is the primary oracle for JVM projects. If it does exist, all other
    # oracles are ignored because the results from all other oracles are subsets
    # of the results from JPC oracle for JVM projects.
    target_oracles = ['jvm-public-candidates']

  for target_oracle in target_oracles:
    tmp_functions = _select_top_functions_from_oracle(project, limit,
                                                      target_oracle,
                                                      target_oracles)
    all_functions.update(tmp_functions)

  return list(all_functions.values())[:limit]

def _select_functions_from_oracles(project: str, limit: int,
                                   target_oracles: list[str]) -> list[dict]:
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

def _get_harness_intrinsics(
    project,
    filenames,
    language='') -> tuple[Optional[str], Optional[str], Dict[str, str]]:
  """Returns a harness source path and executable from a given project."""
  if USE_FI_TO_GET_TARGETS and language != 'jvm' and language != 'python':
    harnesses = query_introspector_for_harness_intrinsics(project)
    if not harnesses:
      logger.error('No harness/source pairs found in project.')
      return None, None, {}

    harness_dict = harnesses[0]
    harness = harness_dict['source']
    target_name = harness_dict['executable']
    interesting_files = {}
  else:
    harnesses, interesting_files = project_src.search_source(
        project, filenames, language)
    harness = pick_one(harnesses)
    if not harness:
      logger.error('No fuzz target found in project %s.', project)
      return None, None, {}
    target_name = get_target_name(project, harness)

  logger.info('Fuzz target file found for project %s: %s', project, harness)
  logger.info('Fuzz target binary found for project %s: %s', project,
              target_name)

  return harness, target_name, interesting_files

def populate_benchmarks_using_test_migration(
    project: str, language: str, limit: int) -> list[benchmarklib.Benchmark]:
  """Populates benchmarks using tests for test-to-harness conversion."""

  harness, target_name, _ = _get_harness_intrinsics(project, [], language)
  if not harness:
    return []

  logger.info('Using harness path %s', harness)
  potential_benchmarks = []
  test_files = query_introspector_for_tests(project)
  for test_file in test_files:
    potential_benchmarks.append(
        benchmarklib.Benchmark(benchmark_id='cli',
                               project=project,
                               language=language,
                               function_signature='test-file',
                               function_name='test-file',
                               return_type='test',
                               params=[],
                               target_path=harness,
                               preferred_target_name=target_name,
                               test_file_path=test_file))
  return potential_benchmarks[:limit]

def generate_benchmark_for_targeted_function(project: str, function_name: str):
  """generates a benchmark for a single function."""
  function_dict = query_introspector_target_function(project, function_name)
  project_lang = oss_fuzz_checkout.get_project_language(project)

  harness, target_name, _ = _get_harness_intrinsics(project, [], project_lang)
  if not harness:
    return ''
  target_benchmarks = [
      benchmarklib.Benchmark(
          benchmark_id='cli',
          project=project,
          language=project_lang,
          function_signature=function_dict.get('function_signature', ''),
          function_name=get_raw_function_name(function_dict, project),
          return_type=_get_clean_return_type(function_dict, project),
          params=_group_function_params(
              _get_clean_arg_types(function_dict, project),
              _get_arg_names(function_dict, project, project_lang),
              project_lang),
          target_path=harness,
          preferred_target_name=target_name,
          function_dict=function_dict)
  ]

  benchmark_dir = get_next_generated_benchmarks_dir()
  os.makedirs(benchmark_dir)
  benchmarklib.Benchmark.to_yaml(target_benchmarks, outdir=benchmark_dir)
  return benchmark_dir

def populate_benchmarks_using_introspector(project: str, language: str,
                                           limit: int,
                                           target_oracles: List[str]):
  """Populates benchmark YAML files from the data from FuzzIntrospector."""

  potential_benchmarks = []
  for target_oracle in target_oracles:
    if 'test-migration' in target_oracle:
      potential_benchmarks.extend(
          populate_benchmarks_using_test_migration(project, language, limit))

  if language == 'jvm':
    functions = _select_functions_from_jvm_oracles(project, limit,
                                                   target_oracles)
  else:
    functions = _select_functions_from_oracles(project, limit, target_oracles)

  if not functions:
    return potential_benchmarks

  if language == 'jvm':
    filenames = [
        f'{function["function_filename"].split("$")[0].replace(".", "/")}.java'
        for function in functions
    ]
  elif language == 'python':
    filenames = [
        (f'{function["function_filename"].replace("...", "").replace(".", "/")}'
         '.py') for function in functions
    ]
  else:
    filenames = [
        os.path.basename(function['function_filename'])
        for function in functions
    ]

  harness, target_name, interesting = _get_harness_intrinsics(
      project, filenames, language)
  if not harness:
    return []

  for function in functions:
    if _get_arg_count(function) == 0:
      # Skipping functions / methods that does not take in any arguments.
      # Those functions / methods are not fuzz-worthy.
      continue

    filename = os.path.basename(function['function_filename'])

    if language == 'python':
      if filename.startswith('...'):
        # Filename of python fuzzers always starts with ...
        # Skipping them
        continue
      if _get_arg_count(function) == 1 and _get_arg_names(
          function, project, language)[0] == 'self':
        # If a python function has only 1 arugment and the argument name
        # is 'self', it means that it is an instance function with no
        # arguments. Thus skipping it.
        continue

    elif language == 'jvm':
      # Retrieve list of source file from introspector
      src_path_list = query_introspector_jvm_source_path(project)
      if src_path_list:
        # For all JVM projects, the full class name is stored in the filename
        # field. The full class name includes the package of the class and that
        # forms part of the directory pattern of the source file that is needed
        # for checking. For example, the source file of class a.b.c.d is always
        # stored as <SOURCE_BASE>/a/b/c/d.java
        if filename.endswith('.java'):
          src_file = filename
        else:
          src_file = f'{filename.replace(".", "/")}.java'

        if not any(src_path.endswith(src_file) for src_path in src_path_list):
          logger.error('error: %s %s', filename, interesting.keys())
          continue

    elif (language not in ['rust'] and interesting and
          filename not in [os.path.basename(i) for i in interesting.keys()]):
      # TODO: Bazel messes up paths to include "/proc/self/cwd/..."
      logger.error('error: %s %s', filename, interesting.keys())
      continue

    function_signature = get_function_signature(function, project)
    if not function_signature:
      continue
    logger.info('Function signature to fuzz: %s', function_signature)
    potential_benchmarks.append(
        benchmarklib.Benchmark(
            benchmark_id='cli',
            project=project,
            language=language,
            function_signature=function_signature,
            function_name=get_raw_function_name(function, project),
            return_type=_get_clean_return_type(function, project),
            params=_group_function_params(
                _get_clean_arg_types(function, project),
                _get_arg_names(function, project, language), language),
            target_path=harness,
            preferred_target_name=target_name,
            function_dict=function))

    if len(potential_benchmarks) >= (limit * len(target_oracles)):
      break
  logger.info('Length of potential targets: %d', len(potential_benchmarks))

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
  """Returns the latest summary in the FuzzIntrospector bucket or local API."""
  # First try to use local introspector endpoint if available
  if INTROSPECTOR_ENDPOINT and INTROSPECTOR_ENDPOINT != DEFAULT_INTROSPECTOR_ENDPOINT:
    try:
      # Try to get project summary from local API
      local_summary_url = f'{INTROSPECTOR_ENDPOINT}/project-summary?project={project_name}'
      response = requests.get(local_summary_url, timeout=10)
      if response.status_code == 200:
        data = response.json()
        if data.get('result') == 'success':
          logger.info('Found project %s in local introspector API', project_name)
          return local_summary_url  # Return the API endpoint
    except Exception as e:
      logger.debug('Local introspector API not available for %s: %s', project_name, e)
  
  # Fallback to Google Cloud Storage
  try:
    client = storage.Client.create_anonymous_client()
    bucket = client.get_bucket('oss-fuzz-introspector')
    blobs = bucket.list_blobs(prefix=project_name)
    summaries = sorted(
        [blob.name for blob in blobs if blob.name.endswith('summary.json')])
    if summaries:
      return ('https://storage.googleapis.com/oss-fuzz-introspector/'
              f'{summaries[-1]}')
  except Exception as e:
    logger.debug('Failed to access cloud storage for %s: %s', project_name, e)
  
  logger.error('Error: %s has no summary.', project_name)
  return None

def _extract_introspector_report(project_name):
  """Queries and extracts FuzzIntrospector report data of |project_name|."""
  project_url = _identify_latest_report(project_name)
  if not project_url:
    return None
  # Read the introspector artifact.
  try:
    raw_introspector_json_request = requests.get(project_url, timeout=10)
    response_data = json.loads(raw_introspector_json_request.text)
    
    # Handle local API response format
    if (INTROSPECTOR_ENDPOINT and 
        INTROSPECTOR_ENDPOINT != DEFAULT_INTROSPECTOR_ENDPOINT and 
        project_url.startswith(INTROSPECTOR_ENDPOINT)):
      # Extract introspector data from local API response
      if response_data.get('result') == 'success':
        return response_data.get('project', {}).get('introspector_data', {})
    
    # Handle cloud storage response (direct JSON)
    return response_data
  except:
    return None

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
    logger.error('No fuzz introspector report is found.')
    return {}

  if introspector_json_report.get('analyses') is None:
    logger.error('Error: introspector_json_report has no "analyses"')
    return {}
  if introspector_json_report.get('analyses').get('AnnotatedCFG') is None:
    logger.error(
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
    logger.error('Failed to prepare OSS-Fuzz directory for project %s: %s',
                 args.project, e)
  cur_project_language = oss_fuzz_checkout.get_project_language(args.project)
  benchmarks = populate_benchmarks_using_introspector(args.project,
                                                      cur_project_language,
                                                      args.max_functions,
                                                      args.target_oracle)
  if benchmarks:
    benchmarklib.Benchmark.to_yaml(benchmarks, outdir=args.out)
  else:
    logger.error('Nothing found for %s', args.project)
    sys.exit(1)
