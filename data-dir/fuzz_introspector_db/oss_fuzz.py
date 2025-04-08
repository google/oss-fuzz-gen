# Copyright 2024 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Utilities for getting data from OSS-Fuzz"""

import json
import os

import constants
import requests
import yaml


def get_introspector_report_url_base(project_name, datestr):
  base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
  project_url = base_url.format(project_name, datestr)
  return project_url


def get_introspector_report_url_summary(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "summary.json"


def get_introspector_report_url_all_functions(project_name, datestr):
  return get_introspector_report_url_base(
      project_name, datestr) + "all-fuzz-introspector-functions.json"


def get_introspector_report_url_jvm_constructor(project_name, datestr):
  return get_introspector_report_url_base(
      project_name, datestr) + "all-fuzz-introspector-jvm-constructor.json"


def get_introspector_report_url_report(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "fuzz_report.html"


def get_fuzzer_stats_fuzz_count_url(project_name, date_str):
  base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/fuzzer_stats/{1}/coverage_targets.txt'
  coverage_targets = base_url.format(project_name, date_str)
  return coverage_targets


def get_introspector_project_tests_url(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "light/all_tests.json"


def get_introspector_project_all_files(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "light/all_files.json"


def get_introspector_light_pairs_url(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "light/all_pairs.json"


def extract_introspector_light_all_pairs(project_name, date_str):
  """Gets the list of pairs from introspector light"""
  debug_data_url = get_introspector_light_pairs_url(project_name,
                                                    date_str.replace("-", ""))
  try:
    raw_introspector_json_request = requests.get(debug_data_url, timeout=10)
  except:
    return []
  try:
    all_pairs = json.loads(raw_introspector_json_request.text)
  except:
    return []

  return all_pairs


def get_introspector_light_tests_url(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "light/all_tests.json"


def extract_introspector_light_all_tests(project_name, date_str):
  """Gets the list of test files from light"""
  debug_data_url = get_introspector_light_tests_url(project_name,
                                                    date_str.replace("-", ""))
  try:
    raw_introspector_json_request = requests.get(debug_data_url, timeout=10)
  except:
    return []
  try:
    all_tests = json.loads(raw_introspector_json_request.text)
  except:
    return []

  return all_tests


def get_introspector_light_all_files_url(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "light/all_files.json"


def extract_introspector_light_all_files(project_name, date_str):
  """Gets the list of all files from light"""
  debug_data_url = get_introspector_light_all_files_url(
      project_name, date_str.replace("-", ""))
  try:
    raw_introspector_json_request = requests.get(debug_data_url, timeout=10)
  except:
    return []
  try:
    all_urls = json.loads(raw_introspector_json_request.text)
  except:
    return []

  return all_urls


def get_introspector_type_map_url_summary(project_name, datestr):
  return get_introspector_report_url_base(
      project_name, datestr) + "all-friendly-debug-types.json"


def get_fuzzer_stats_fuzz_count(project_name, date_str):
  coverage_stats_url = get_fuzzer_stats_fuzz_count_url(project_name, date_str)
  try:
    coverage_summary_raw = requests.get(coverage_stats_url, timeout=20).text
  except:
    return None

  if "The specified key does not exist" in coverage_summary_raw:
    return None
  return coverage_summary_raw


def get_code_coverage_summary_url(project_name, datestr):
  base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/summary.json'
  project_url = base_url.format(project_name, datestr)
  return project_url


def get_fuzzer_code_coverage_summary_url(project_name, datestr, fuzzer):
  base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports-by-target/{1}/{2}/linux/summary.json'
  project_url = base_url.format(project_name, datestr, fuzzer)
  return project_url


def get_coverage_report_url(project_name, datestr, language):
  if language == 'java' or language == 'python' or language == 'go':
    file_report = "index.html"
  else:
    file_report = "report.html"
  base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'
  project_url = base_url.format(project_name, datestr, file_report)
  return project_url


def get_introspector_report_url_debug_info(project_name, datestr):
  return get_introspector_report_url_base(project_name,
                                          datestr) + "all_debug_info.json"


def extract_introspector_debug_info(project_name, date_str):
  debug_data_url = get_introspector_report_url_debug_info(
      project_name, date_str.replace("-", ""))
  #print("Getting: %s" % (introspector_summary_url))
  # Read the introspector atifact
  try:
    raw_introspector_json_request = requests.get(debug_data_url, timeout=10)
  except:
    return dict()
  try:
    debug_report = json.loads(raw_introspector_json_request.text)
  except:
    return dict()

  return debug_report


def extract_local_introspector_function_list(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector',
                              'all-fuzz-introspector-functions.json')
  if not os.path.isfile(summary_json):
    return []

  with open(summary_json, 'r') as f:
    function_list = json.load(f)
  return function_list


def extract_local_introspector_constructor_list(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector',
                              'all-fuzz-introspector-jvm-constructor.json')
  if not os.path.isfile(summary_json):
    return []

  with open(summary_json, 'r') as f:
    function_list = json.load(f)
  return function_list


def extract_local_introspector_report(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'summary.json')
  if not os.path.isfile(summary_json):
    return {}

  with open(summary_json, 'r') as f:
    json_dict = json.load(f)
  return json_dict


def get_local_code_coverage_summary(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'report', 'linux', 'summary.json')
  if not os.path.isfile(summary_json):
    return None
  with open(summary_json, 'r') as f:
    json_dict = json.load(f)
  return json_dict


def get_local_code_coverage_stats(project_name, oss_fuzz_folder):
  coverage_targets = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                  'fuzzer_stats', 'coverage_targets.txt')
  if not os.path.isfile(coverage_targets):
    return None
  with open(coverage_targets, 'r') as f:
    content = f.read()
  return content


def get_code_coverage_summary(project_name, datestr):
  cov_summary_url = get_code_coverage_summary_url(project_name, datestr)
  try:
    coverage_summary_raw = requests.get(cov_summary_url, timeout=20).text
  except:
    return None
  try:
    json_dict = json.loads(coverage_summary_raw)
    return json_dict
  except:
    return None


def get_fuzzer_code_coverage_summary(project_name, datestr, fuzzer):
  cov_summary_url = get_fuzzer_code_coverage_summary_url(
      project_name, datestr, fuzzer)
  try:
    coverage_summary_raw = requests.get(cov_summary_url, timeout=20).text
  except:
    return None
  try:
    json_dict = json.loads(coverage_summary_raw)
    return json_dict
  except:
    return None


def extract_new_introspector_functions(project_name, date_str):
  introspector_functions_url = get_introspector_report_url_all_functions(
      project_name, date_str.replace("-", ""))

  # Read the introspector artifact
  try:
    raw_introspector_json_request = requests.get(introspector_functions_url,
                                                 timeout=10)
    introspector_functions = json.loads(raw_introspector_json_request.text)
  except:
    return []

  return introspector_functions


def extract_new_introspector_constructors(project_name, date_str):
  introspector_constructor_url = get_introspector_report_url_jvm_constructor(
      project_name, date_str.replace("-", ""))

  # Read the introspector artifact
  try:
    raw_introspector_json_request = requests.get(introspector_constructor_url,
                                                 timeout=10)
    introspector_constructors = json.loads(raw_introspector_json_request.text)
  except:
    return []

  return introspector_constructors


def extract_introspector_all_files(project_name, date_str):
  introspector_all_files_url = get_introspector_project_all_files(
      project_name, date_str.replace("-", ""))

  # Read the introspector atifact
  try:
    raw_introspector_json_request = requests.get(introspector_all_files_url,
                                                 timeout=10)
  except:
    return None
  try:
    all_files = json.loads(raw_introspector_json_request.text)
  except:
    return None

  return all_files


def extract_introspector_test_files(project_name, date_str):
  introspector_test_url = get_introspector_project_tests_url(
      project_name, date_str.replace("-", ""))

  # Read the introspector atifact
  try:
    raw_introspector_json_request = requests.get(introspector_test_url,
                                                 timeout=10)
  except:
    return None
  try:
    test_files = json.loads(raw_introspector_json_request.text)
  except:
    return None

  return test_files


def extract_introspector_report(project_name, date_str):
  introspector_summary_url = get_introspector_report_url_summary(
      project_name, date_str.replace("-", ""))
  introspector_report_url = get_introspector_report_url_report(
      project_name, date_str.replace("-", ""))

  # Read the introspector atifact
  try:
    raw_introspector_json_request = requests.get(introspector_summary_url,
                                                 timeout=10)
  except:
    return None
  try:
    introspector_report = json.loads(raw_introspector_json_request.text)
  except:
    return None

  return introspector_report


def extract_local_introspector_all_files(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'all-files.json')
  if not os.path.isfile(summary_json):
    return []
  with open(summary_json, 'r') as f:
    json_list = json.load(f)
  return json_list


def extract_local_introspector_test_files(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'test-files.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_list = json.load(f)
  return json_list


def extract_local_introspector_light_test_files(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'light', 'all_tests.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_list = json.load(f)
  return json_list


def extract_local_introspector_light_pairs(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'light', 'all_pairs.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_list = json.load(f)
  return json_list


def extract_local_introspector_light_all_files(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'light', 'all_files.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_list = json.load(f)
  return json_list


def extract_local_introspector_debug_info(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'all_debug_info.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_dict = json.load(f)
  return json_dict


def get_local_introspector_type_map(project_name, oss_fuzz_folder):
  summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                              'inspector', 'all-friendly-debug-types.json')
  if not os.path.isfile(summary_json):
    return {}
  with open(summary_json, 'r') as f:
    json_dict = json.load(f)
  return json_dict


def get_introspector_type_map(project_name, date_str):
  introspector_type_api_url = get_introspector_type_map_url_summary(
      project_name, date_str.replace("-", ""))

  # Read the introspector atifact
  try:
    raw_introspector_json_request = requests.get(introspector_type_api_url,
                                                 timeout=10)
  except:
    return None
  try:
    introspector_type_map = json.loads(raw_introspector_json_request.text)
  except:
    return None

  return introspector_type_map


def get_projects_build_status():
  fuzz_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.FUZZ_BUILD_JSON
  coverage_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.COVERAGE_BUILD_JSON
  introspector_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.INTROSPECTOR_BUILD_JSON

  fuzz_build_raw = requests.get(fuzz_build_url, timeout=20).text
  coverage_build_raw = requests.get(coverage_build_url, timeout=20).text
  introspector_build_raw = requests.get(introspector_build_url, timeout=20).text

  fuzz_build_json = json.loads(fuzz_build_raw)
  cov_build_json = json.loads(coverage_build_raw)
  introspector_build_json = json.loads(introspector_build_raw)

  build_status_dict = dict()
  for p in fuzz_build_json['projects']:
    project_dict = build_status_dict.get(p['name'], dict())
    project_dict['fuzz-build'] = p['history'][0]['success']
    project_dict['fuzz-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
        'history'][0]['build_id'] + '.txt'
    build_status_dict[p['name']] = project_dict
  for p in cov_build_json['projects']:
    project_dict = build_status_dict.get(p['name'], dict())
    project_dict['cov-build'] = p['history'][0]['success']
    project_dict['cov-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
        'history'][0]['build_id'] + '.txt'
    build_status_dict[p['name']] = project_dict
  for p in introspector_build_json['projects']:
    project_dict = build_status_dict.get(p['name'], dict())
    project_dict['introspector-build'] = p['history'][0]['success']
    project_dict[
        'introspector-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
            'history'][0]['build_id'] + '.txt'
    build_status_dict[p['name']] = project_dict

  # Ensure all fields are set in each dictionary
  needed_keys = [
      'introspector-build', 'fuzz-build', 'cov-build', 'introspector-build-log',
      'cov-build-log', 'fuzz-build-log'
  ]
  for project_name in build_status_dict:
    project_dict = build_status_dict[project_name]
    for needed_key in needed_keys:
      if needed_key not in project_dict:
        project_dict[needed_key] = 'N/A'

  print("Going through all of the projects")
  for project_name in build_status_dict:
    project_language = try_to_get_project_language(project_name)
    build_status_dict[project_name]['language'] = project_language
  print("Number of projects: %d" % (len(build_status_dict)))
  return build_status_dict


def try_to_get_project_language(project_name):
  if os.path.isdir(constants.OSS_FUZZ_CLONE):
    local_project_path = os.path.join(constants.OSS_FUZZ_CLONE, "projects",
                                      project_name)
    if os.path.isdir(local_project_path):
      project_yaml_path = os.path.join(local_project_path, "project.yaml")
      if os.path.isfile(project_yaml_path):
        with open(project_yaml_path, "r") as f:
          project_yaml = yaml.safe_load(f.read())
          return project_yaml['language']
  else:
    proj_yaml_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master/projects/%s/project.yaml' % (
        project_name)
    try:
      r = requests.get(proj_yaml_url, timeout=10)
    except:
      return "N/A"
    project_yaml = yaml.safe_load(r.text)
    return project_yaml['language']
  return "N/A"


def try_to_get_project_repository(project_name):
  if os.path.isdir(constants.OSS_FUZZ_CLONE):
    local_project_path = os.path.join(constants.OSS_FUZZ_CLONE, "projects",
                                      project_name)
    if os.path.isdir(local_project_path):
      project_yaml_path = os.path.join(local_project_path, "project.yaml")
      if os.path.isfile(project_yaml_path):
        with open(project_yaml_path, "r") as f:
          project_yaml = yaml.safe_load(f.read())
          return project_yaml['main_repo']
  else:
    proj_yaml_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master/projects/%s/project.yaml' % (
        project_name)
    try:
      r = requests.get(proj_yaml_url, timeout=10)
    except:
      return "N/A"
    project_yaml = yaml.safe_load(r.text)
    return project_yaml['main_repo']
  return "N/A"
