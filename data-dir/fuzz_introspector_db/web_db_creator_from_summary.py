# Copyright 2023 Fuzz Introspector Authors
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
"""Helper for creating the necessary .json files used by the webapp."""
import io
import os
import argparse
import json
import orjson
import shutil
import logging
import datetime
import requests
import subprocess
import zipfile
import tarfile
import statistics
from pathlib import Path
import concurrent
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import List, Any, Optional, Dict, Tuple, Set

import constants
import oss_fuzz

DB_JSON_DB_TIMESTAMP = 'db-timestamps.json'
DB_JSON_ALL_PROJECT_TIMESTAMP = 'all-project-timestamps.json'
DB_JSON_ALL_FUNCTIONS = 'all-functions-db-{PROJ}.json'
DB_JSON_ALL_CONSTRUCTORS = 'all-constructors-db-{PROJ}.json'
DB_JSON_ALL_CURRENT = 'all-project-current.json'
DB_JSON_ALL_BRANCH_BLOCKERS = 'all-branch-blockers.json'
DB_BUILD_STATUS_JSON = 'build-status.json'
#DB_RAW_INTROSPECTOR_REPORTS = 'raw-introspector-reports'

ALL_JSON_FILES = [
    DB_JSON_DB_TIMESTAMP,
    DB_JSON_ALL_PROJECT_TIMESTAMP,
    DB_JSON_ALL_FUNCTIONS,
    DB_JSON_ALL_CONSTRUCTORS,
    DB_JSON_ALL_CURRENT,
]

INTROSPECTOR_WEBAPP_ZIP = (
    'https://introspector.oss-fuzz.com/static/assets/db/db-archive.zip')

FI_EXCLUDE_ALL_NON_MUSTS = bool(int(os.getenv('FI_EXCLUDE_ALL_NON_MUSTS',
                                              '0')))

NUM_RECENT_DAYS = 30
FUZZER_COVERAGE_IS_DEGRADED = 5  # 5% or more is a degradation

MUST_INCLUDES = set()
MUST_INCLUDE_WITH_LANG: List[Any] = []

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger(name=__name__)


def git_clone_project(git_url: str, destination: str) -> bool:
    """Clones a Git repository into a given destination folder."""
    cmd = ["git clone", git_url, destination]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=600,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        logger.info("Timed out cloning %s", git_url)
        return False
    except subprocess.CalledProcessError:
        logger.info("Error cloning %s", git_url)
        return False
    return True


def rename_annotated_cfg(original_annotated_cfg):
    """Renames an annotated CFG as it is from introspector."""
    new_annotated_cfg = list()
    for fuzzer_name in original_annotated_cfg:
        elem = {
            'fuzzer_name': fuzzer_name,
            'source_file': original_annotated_cfg[fuzzer_name]['src_file'],
            'destinations': []
        }
        for dest_elem in original_annotated_cfg[fuzzer_name]['destinations']:
            refined_dest_elem = dict()
            for k, v in dest_elem.items():
                refined_dest_elem[k.replace("-", "_")] = v
            elem['destinations'].append(refined_dest_elem)

        new_annotated_cfg.append(elem)
    return new_annotated_cfg


def save_fuzz_introspector_report(introspector_report, project_name, date_str):
    # Disable for now to avoid growing the disk too much
    #os.makedirs(DB_RAW_INTROSPECTOR_REPORTS, exist_ok=True)

    #report_dst = os.path.join(DB_RAW_INTROSPECTOR_REPORTS,
    #                          '%s-%s.json' % (project_name, date_str))
    #with open(report_dst, 'w') as report_fd:
    #    json.dump(introspector_report, report_fd)
    return


def save_test_files_report(test_files, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'test_files.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(test_files, report_fd)


def save_all_files_report(all_files, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'all_files.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(all_files, report_fd)


def save_debug_report(debug_report, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'debug_report.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(debug_report, report_fd)


def save_branch_blockers(branch_blockers, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'branch_blockers.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(branch_blockers, report_fd)


def save_type_map(debug_report, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'type_map.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(debug_report, report_fd)


def extract_and_refine_branch_blockers(introspector_report, project_name):
    branch_pairs = list()
    for key in introspector_report:
        if key == "MergedProjectProfile" or key == 'analyses':
            continue

        # Fuzzer-specific dictionary, get the contents of it.
        val = introspector_report[key]
        if not isinstance(val, dict):
            continue

        branch_blockers = val.get('branch_blockers', None)
        if branch_blockers is None or not isinstance(branch_blockers, list):
            continue

        for branch_blocker in branch_blockers:
            function_blocked = branch_blocker.get('function_name', None)
            blocked_unique_not_covered_complexity = branch_blocker.get(
                'blocked_unique_not_covered_complexity', None)
            if blocked_unique_not_covered_complexity < 5:
                continue
            if function_blocked is None:
                continue
            if blocked_unique_not_covered_complexity is None:
                continue

            branch_pairs.append({
                'project':
                project_name,
                'function_name':
                function_blocked,
                'blocked_runtime_coverage':
                blocked_unique_not_covered_complexity,
                'source_file':
                branch_blocker.get('source_file', "N/A"),
                'linenumber':
                branch_blocker.get('branch_line_number', -1),
                'blocked_unique_functions':
                branch_blocker.get('blocked_unique_functions', [])
            })
    return branch_pairs


def extract_and_refine_annotated_cfg(introspector_report):
    annotated_cfg = dict()
    for key in introspector_report:
        # We look for dicts with fuzzer-specific content. The following two
        # are not such keys, so skip them.
        if key == 'analyses':
            if 'AnnotatedCFG' in introspector_report[key]:
                annotated_cfg = rename_annotated_cfg(
                    introspector_report['analyses']['AnnotatedCFG'])
    return annotated_cfg


def extract_and_refine_functions(all_function_list, date_str):
    refined_proj_list = []

    for func in all_function_list:
        introspector_func = {
            'name':
            func['Func name'],
            'cov_url':
            func['func_url'].replace(
                "https://storage.googleapis.com/oss-fuzz-coverage/", ""),
            'file':
            func['Functions filename'],
            'cov':
            float(func['Func lines hit %'].replace("%", "")),
            'fuzzers':
            func['Reached by Fuzzers'],
            'acc_cc':
            func['Accumulated cyclomatic complexity'],
            'icount':
            func['I Count'],
            'u-cc':
            func['Undiscovered complexity'],
            'args':
            func['Args'],
            'args-names':
            func.get('ArgNames', ['Did not find arguments']),
            'rtn':
            func.get('return_type', 'N/A'),
            'raw-name':
            func.get('raw-function-name', 'N/A'),
            'date-str':
            date_str,
            'src_begin':
            func.get('source_line_begin', 'N/A'),
            'src_end':
            func.get('source_line_end', 'N/A'),
            'callsites':
            func.get('callsites', [])
        }

        introspector_func['sig'] = func.get('function_signature', 'N/A')
        introspector_func['debug'] = func.get('debug_function_info', dict())
        introspector_func['access'] = func.get('is_accessible', True)
        introspector_func['jvm_lib'] = func.get('is_jvm_library', False)
        introspector_func['enum'] = func.get('is_enum_class', False)
        introspector_func['static'] = func.get('is_static', False)
        introspector_func['need_close'] = func.get('need_close', False)
        introspector_func['exc'] = func.get('exceptions', [])

        # For JVM projects, the function name, function signature and function raw
        # name should be the same. Remove them to avoid duplication and reduce the
        # db size if they are indeed the same.
        if introspector_func['sig'] == introspector_func['name']:
            del introspector_func['sig']
        if introspector_func['raw-name'] == introspector_func['name']:
            del introspector_func['raw-name']

        # There is a bug in Fuzz-Introspector report generation that sets function
        # call depth as a list instead of an integer in the JSON reports. Although
        # the bug has been fixed in PR#1675, older JSON reports may still contain
        # a list of a single integer instead of an integer. The logic here retrieves
        # the function call depth from JSON reports, assuming that the function call
        # depth could be an integer or a list of a single integer, for backward
        # compatibility of old JSON reports.
        calldepth = func.get('Function call depth', 0)
        if calldepth and isinstance(calldepth, list):
            calldepth = calldepth[0]
        introspector_func['calldepth'] = calldepth

        refined_proj_list.append(introspector_func)
    return refined_proj_list


def extract_code_coverage_data(code_coverage_summary):
    """Extract the coverage data from a loaded coverage summary.json"""
    # Extract data from the code coverage reports
    if code_coverage_summary is None:
        return None

    try:
        line_total_summary = code_coverage_summary['data'][0]['totals'][
            'lines']
    except KeyError:
        # This can happen in Python, where the correct code formatting was only done
        # May 3rd 2023: https://github.com/google/oss-fuzz/pull/10201
        return None
    #line_total_summary['percent']
    # For the sake of consistency, we re-calculate the percentage. This is because
    # some of the implentations have a value 0 <= p <= 1 and some have 0 <= p <= 100.
    try:
        line_total_summary['percent'] = round(
            100.0 * (float(line_total_summary['covered']) /
                     float(line_total_summary['count'])), 2)
    except:
        pass

    return line_total_summary


def prepare_code_coverage_dict(
        code_coverage_summary, project_name: str, date_str: str,
        project_language: str) -> Optional[Dict[str, Any]]:
    """Gets coverage URL and line coverage total of a project"""
    line_total_summary = extract_code_coverage_data(code_coverage_summary)
    if line_total_summary is None:
        return None

    coverage_url = oss_fuzz.get_coverage_report_url(project_name,
                                                    date_str.replace('-', ''),
                                                    project_language)
    code_coverage_data_dict = {
        'coverage_url': coverage_url,
        'line_coverage': line_total_summary
    }
    return code_coverage_data_dict


def extract_local_project_data(project_name, oss_fuzz_path,
                               manager_return_dict):
    """Extracts data for a project using a local OSS-Fuzz output."""
    print(f'Analysing {project_name}')
    try:
        project_language = oss_fuzz.try_to_get_project_language(project_name)
        if project_language == 'jvm':
            project_language = 'java'
    except:
        # Default set to c++ as this is OSS-Fuzz's default.
        project_language = 'c++'

    code_coverage_summary = oss_fuzz.get_local_code_coverage_summary(
        project_name, oss_fuzz_path)
    cov_fuzz_stats = oss_fuzz.get_local_code_coverage_stats(
        project_name, oss_fuzz_path)
    introspector_report = oss_fuzz.extract_local_introspector_report(
        project_name, oss_fuzz_path)
    introspector_type_map = oss_fuzz.get_local_introspector_type_map(
        project_name, oss_fuzz_path)
    debug_report = oss_fuzz.extract_local_introspector_debug_info(
        project_name, oss_fuzz_path)
    test_files = oss_fuzz.extract_local_introspector_test_files(
        project_name, oss_fuzz_path)
    if test_files:
        save_test_files_report(test_files, project_name)

    light_test_files = oss_fuzz.extract_local_introspector_light_test_files(
        project_name, oss_fuzz_path)
    light_all_files = oss_fuzz.extract_local_introspector_light_all_files(
        project_name, oss_fuzz_path)
    light_all_pairs = oss_fuzz.extract_local_introspector_light_pairs(
        project_name, oss_fuzz_path)

    light_report = {
        'test-files': light_test_files,
        'all-files': light_all_files,
        'all-pairs': light_all_pairs,
    }

    all_files = oss_fuzz.extract_local_introspector_all_files(
        project_name, oss_fuzz_path)
    if all_files:
        new_all_files = []
        for file in all_files:
            if '/src/inspector/source-code/' in file:
                continue
            new_all_files.append(file)
        save_all_files_report(new_all_files, project_name)

    if debug_report:
        all_files_in_project = debug_report.get('all_files_in_project', [])
        all_header_files_in_project = set()
        for elem in all_files_in_project:
            source_file = elem.get('source_file', '')
            if source_file.endswith('.h'):
                normalized_file = os.path.normpath(source_file)
                if '/usr/local/' in normalized_file or '/usr/include/' in normalized_file:
                    continue
                all_header_files_in_project.add(normalized_file)

        all_header_files = {
            'project': project_name.split('###')[0],
            'all-header-files': list(all_header_files_in_project)
        }
    else:
        all_header_files = {
            'project': project_name.split('###')[0],
            'all-header-files': list()
        }

    # Refine the data
    all_function_list = oss_fuzz.extract_local_introspector_function_list(
        project_name, oss_fuzz_path)
    all_constructor_list = oss_fuzz.extract_local_introspector_constructor_list(
        project_name, oss_fuzz_path)

    try:
        project_stats = introspector_report['MergedProjectProfile']['stats']
    except KeyError:
        project_stats = {}
    amount_of_fuzzers = project_stats.get('harness-count', 0)
    functions_covered_estimate = project_stats.get(
        'code-coverage-function-percentage', 0.0)

    # Get details if needed and otherwise leave empty
    refined_proj_list = list()
    annotated_cfg = dict()

    refined_proj_list = extract_and_refine_functions(all_function_list, '')
    refined_constructor_list = extract_and_refine_functions(
        all_constructor_list, '')
    annotated_cfg = extract_and_refine_annotated_cfg(introspector_report)

    # Dump things we dont want to accummulate.
    #save_branch_blockers(branch_pairs, project_name)
    try:
        project_repository = oss_fuzz.try_to_get_project_repository(
            project_name)
    except:
        project_repository = 'N/A'

    introspector_data_dict = {
        "introspector_report_url":
        'introspector_url',
        "coverage_lines":
        project_stats.get('code-coverage-function-percentage', 0.0),
        "static_reachability":
        project_stats.get('reached-complexity-percentage', 0.0),
        "fuzzer_count":
        amount_of_fuzzers,
        "function_count":
        len(all_function_list),
        "functions_covered_estimate":
        functions_covered_estimate,
        'refined_proj_list':
        refined_proj_list,
        'refined_constructor_list':
        refined_constructor_list,
        'annotated_cfg':
        annotated_cfg,
        'project_name':
        project_name
    }

    code_coverage_data_dict = prepare_code_coverage_dict(
        code_coverage_summary, project_name, '', project_language)

    if cov_fuzz_stats is not None:
        all_fuzzers = cov_fuzz_stats.split("\n")
        if all_fuzzers[-1] == '':
            all_fuzzers = all_fuzzers[0:-1]
        amount_of_fuzzers = len(all_fuzzers)

    project_timestamp = {
        "project_name": project_name,
        "date": '',
        'language': project_language,
        'coverage-data': code_coverage_data_dict,
        'introspector-data': introspector_data_dict,
        'fuzzer-count': amount_of_fuzzers,
        'project_repository': project_repository,
        'light-introspector': light_report,
    }

    dictionary_key = '%s###%s' % (project_name, '')
    manager_return_dict[dictionary_key] = {
        'project_timestamp': project_timestamp,
        'introspector-data-dict': introspector_data_dict,
        'coverage-data-dict': code_coverage_data_dict,
        'all-header-files': all_header_files,
    }


def extract_project_data(project_name, date_str, should_include_details,
                         manager_return_dict):
    """
    Extracts data about a given project on a given date. The data will be placed
    in manager_return dict.

    The data that will be exracted include:
    - Details extracted from introspector reports
        - Function profiles
        - Static reachability
        - Number of fuzzers
    - Details extracted from code coverage reports
        - Lines of code totally in the project
        - Lines of code covered at runtime
    """
    amount_of_fuzzers = None
    # TODO (David): handle the case where there is neither code coverage or introspector reports.
    # In this case we should simply return an error so it will not be included. This is also useful
    # for creating history

    # Extract programming language of the project
    # The previous techniques we used to set language was quite heuristically.
    # Here, we make a more precise effort by reading the project yaml file.
    try:
        project_language = oss_fuzz.try_to_get_project_language(project_name)
        if project_language == 'jvm':
            project_language = 'java'
    except Exception:  # pylint: disable=W0718
        # Default set to c++ as this is OSS-Fuzz's default.
        project_language = 'c++'

    try:
        project_repository = oss_fuzz.try_to_get_project_repository(
            project_name)
    except Exception:  # pylint: disable=W0718
        project_repository = 'N/A'

    collect_debug_info = project_language in {'c', 'c++'}

    # Extract code coverage and introspector reports.
    code_coverage_summary = oss_fuzz.get_code_coverage_summary(
        project_name, date_str.replace("-", ""))
    cov_fuzz_stats = oss_fuzz.get_fuzzer_stats_fuzz_count(
        project_name, date_str.replace("-", ""))

    # Get introspector reports for languages with introspector support
    if project_language in {'c', 'c++', 'python', 'java'}:
        introspector_report = oss_fuzz.extract_introspector_report(
            project_name, date_str)
    else:
        introspector_report = None

    introspector_report_url = oss_fuzz.get_introspector_report_url_report(
        project_name, date_str.replace("-", ""))

    test_files = oss_fuzz.extract_introspector_test_files(
        project_name, date_str.replace("-", ""))
    if test_files:
        save_test_files_report(test_files, project_name)

    all_files = oss_fuzz.extract_introspector_all_files(
        project_name, date_str.replace("-", ""))
    if all_files:
        new_all_files = []
        for file in all_files:
            if '/src/inspector/source-code/' in file:
                continue
            new_all_files.append(file)
        save_all_files_report(new_all_files, project_name)

    # Collet debug informaiton for languages with debug information
    # Disable dumping type map for now because it takes too much storage.
    # TODO(David): find a better solution wrt storage here. Maybe download the
    # files on the fly, or reduce the size significantly.
    dump_type_map = False
    if dump_type_map and collect_debug_info:
        introspector_type_map = oss_fuzz.get_introspector_type_map(
            project_name, date_str.replace("-", ""))
    else:
        introspector_type_map = None

    #print("Type mapping:")
    if dump_type_map and should_include_details and introspector_type_map:
        # Remove the friendly types from the type map because they take up
        # too much space. Instead, extract this at runtime when it need to be used.
        for addr, value in introspector_type_map.items():
            if 'friendly-info' in value:
                del value['friendly-info']

        # Remove the raw_debug_info from the type
        for addr in introspector_type_map:
            if 'raw_debug_info' in introspector_type_map[addr]:
                introspector_type_map[addr] = introspector_type_map[addr][
                    'raw_debug_info']

                if len(introspector_type_map[addr].get('enum_elems', [])) == 0:
                    del introspector_type_map[addr]['enum_elems']
                if 'type_idx' in introspector_type_map[addr]:
                    del introspector_type_map[addr]['type_idx']

        save_type_map(introspector_type_map, project_name)
    #    for addr in introspector_type_map:
    #        print("Addr: %s"%(str(addr)))

    # Save the report
    save_fuzz_introspector_report(introspector_report, project_name, date_str)

    light_test_files = oss_fuzz.extract_introspector_light_all_tests(
        project_name, date_str.replace("-", ""))
    light_all_files = oss_fuzz.extract_introspector_light_all_files(
        project_name, date_str.replace("-", ""))
    light_all_pairs = oss_fuzz.extract_introspector_light_all_pairs(
        project_name, date_str.replace("-", ""))

    light_report = {
        'test-files': light_test_files,
        'all-files': light_all_files,
        'all-pairs': light_all_pairs,
    }

    # Get debug data
    if collect_debug_info and should_include_details:
        debug_report = oss_fuzz.extract_introspector_debug_info(
            project_name, date_str)
        save_debug_report(debug_report, project_name)
    else:
        debug_report = None

    if debug_report:
        all_files_in_project = debug_report.get('all_files_in_project', [])
        all_header_files_in_project = set()
        for elem in all_files_in_project:
            source_file = elem.get('source_file', '')
            if source_file.endswith('.h'):
                normalized_file = os.path.normpath(source_file)
                if '/usr/local/' in normalized_file or '/usr/include/' in normalized_file:
                    continue
                all_header_files_in_project.add(normalized_file)

        all_header_files = {
            'project': project_name.split('###')[0],
            'all-header-files': list(all_header_files_in_project)
        }
    else:
        all_header_files = {
            'project': project_name.split('###')[0],
            'all-header-files': list()
        }

    # Currently, we fail if any of code_coverage_summary of introspector_report is
    # None. This should later be adjusted such that we can continue if we only
    # have code coverage but no introspector data. However, we need to adjust
    # the OSS-Fuzz data generated before doing so, we need some basic stats e.g.
    # number of fuzzers, which are currently only available in Fuzz Introspector.
    #if code_coverage_summary == None and introspector_report == None:
    #    # Do not adjust the `manager_return_dict`, so nothing will be included in
    #    # the report.
    #   return

    # We need either:
    # - coverage + fuzzer stats
    # - introspector
    # - both
    if not ((code_coverage_summary != None and cov_fuzz_stats != None)
            or introspector_report != None):
        return

    if introspector_report is None:
        introspector_data_dict = None
    else:
        # Access all functions
        project_stats = introspector_report['MergedProjectProfile']['stats']
        if 'all-functions' in introspector_report['MergedProjectProfile']:
            # Old style
            print('Using old style function storage')
            all_function_list = introspector_report['MergedProjectProfile'][
                'all-functions']
            amount_of_fuzzers = len(introspector_report) - 2
            number_of_functions = len(all_function_list)
        else:
            amount_of_fuzzers = project_stats['harness-count']
            number_of_functions = project_stats['total-functions']
            all_function_list = None

        functions_covered_estimate = project_stats[
            'code-coverage-function-percentage']

        optimal_targets = introspector_report.get('analyses', {}).get(
            'OptimalTargets', [])

        # Get details if needed and otherwise leave empty
        refined_proj_list = list()
        refined_constructor_list = list()
        branch_pairs = list()
        annotated_cfg = dict()
        if should_include_details:
            # Extract all function list
            if all_function_list is None:
                all_function_list = oss_fuzz.extract_new_introspector_functions(
                    project_name, date_str)
            all_constructor_list = oss_fuzz.extract_new_introspector_constructors(
                project_name, date_str)

            refined_proj_list = extract_and_refine_functions(
                all_function_list, date_str)
            refined_constructor_list = extract_and_refine_functions(
                all_constructor_list, date_str)

            annotated_cfg = extract_and_refine_annotated_cfg(
                introspector_report)
            branch_pairs = extract_and_refine_branch_blockers(
                introspector_report, project_name)

        # Dump things we dont want to accummulate.
        save_branch_blockers(branch_pairs, project_name)

        introspector_data_dict = {
            "introspector_report_url": introspector_report_url,
            "coverage_lines":
            project_stats['code-coverage-function-percentage'],
            "static_reachability":
            project_stats['reached-complexity-percentage'],
            "fuzzer_count": amount_of_fuzzers,
            "function_count": number_of_functions,
            "functions_covered_estimate": functions_covered_estimate,
            'refined_proj_list': refined_proj_list,
            'refined_constructor_list': refined_constructor_list,
            'annotated_cfg': annotated_cfg,
            'optimal_targets': optimal_targets,
            'project_name': project_name
        }

    code_coverage_data_dict = prepare_code_coverage_dict(
        code_coverage_summary, project_name, date_str, project_language)

    per_fuzzer_cov = {}
    if cov_fuzz_stats is not None:
        all_fuzzers = cov_fuzz_stats.split("\n")
        if all_fuzzers[-1] == '':
            all_fuzzers = all_fuzzers[0:-1]

        amount_of_fuzzers = len(all_fuzzers)
        for ff in all_fuzzers:
            try:
                fuzzer_cov = oss_fuzz.get_fuzzer_code_coverage_summary(
                    project_name, date_str.replace("-", ""), ff)
                fuzzer_cov_data = extract_code_coverage_data(fuzzer_cov)
                per_fuzzer_cov[ff] = fuzzer_cov_data
            except:
                pass

    project_timestamp = {
        "project_name": project_name,
        "date": date_str,
        'language': project_language,
        'coverage-data': code_coverage_data_dict,
        'per-fuzzer-coverage-data': per_fuzzer_cov,
        'introspector-data': introspector_data_dict,
        'fuzzer-count': amount_of_fuzzers,
        'project_repository': project_repository,
        'light-introspector': light_report,
    }

    dictionary_key = '%s###%s' % (project_name, date_str)
    manager_return_dict[dictionary_key] = {
        'project_timestamp': project_timestamp,
        "introspector-data-dict": introspector_data_dict,
        "coverage-data-dict": code_coverage_data_dict,
        'all-header-files': all_header_files,
    }

    return


def analyse_list_of_projects(date, projects_to_analyse,
                             should_include_details):
    """Creates a DB snapshot of a list of projects for a given date.

    Returns:
    - A db timestamp, which holds overall stats about the database on a given date.
    - A list of all functions for this date if `should_include_details` is True.
    - A list of all constructors for this date if `should_include_details` is True.
    - A list of all branch blockers on this given date if `should_include_details` is True.
    - A list of project timestamps with information about each project.
      - This holds data relative to whether coverage and introspector builds succeeds.

    """
    function_dict = dict()
    constructor_dict = dict()
    project_timestamps = list()
    all_header_files = list()

    # Create a DB timestamp
    db_timestamp = {
        "date": date,
        "project_count": -1,
        "fuzzer_count": 0,
        "function_count": 0,
        "function_coverage_estimate": 0,
        "accummulated_lines_total": 0,
        "accummulated_lines_covered": 0,
    }

    idx = 0
    jobs = []
    analyses_dictionary = dict()
    sem_count = 20 if not should_include_details else 1
    project_name_list = list(projects_to_analyse.keys())

    executor = ThreadPoolExecutor(max_workers=sem_count)
    futures = []
    logger.info('Extracting data for all')
    for project_name in project_name_list:
        futures.append(
            executor.submit(extract_project_data, project_name, date,
                            should_include_details, analyses_dictionary))

    # wait for all tasks to complete
    logger.info('Waiting for completion.')
    concurrent.futures.wait(futures,
                            return_when=concurrent.futures.ALL_COMPLETED)
    logger.info('Completion done.')
    executor.shutdown()

    # Accummulate the data from all the projects.
    for project_info in analyses_dictionary.values():
        # Append project timestamp to the list of timestamps
        project_timestamp = project_info['project_timestamp']
        project_timestamps.append(project_timestamp)
        db_timestamp['fuzzer_count'] += project_timestamp['fuzzer-count']

        # Accummulate all function list and branch blockers
        introspector_dictionary = project_timestamp.get(
            'introspector-data', None)

        if introspector_dictionary is not None:
            proj = introspector_dictionary['project_name']
            # Functions
            if proj in function_dict:
                function_dict[proj].extend(
                    introspector_dictionary['refined_proj_list'])
            else:
                function_dict[proj] = introspector_dictionary[
                    'refined_proj_list']
            # Remove the function list because we don't want it anymore.
            introspector_dictionary.pop('refined_proj_list')

            # Constructors
            if proj in constructor_dict:
                constructor_dict[proj].extend(
                    introspector_dictionary['refined_constructor_list'])
            else:
                constructor_dict[proj] = introspector_dictionary[
                    'refined_constructor_list']
            # Remove the constructor list because we don't want it anymore.
            introspector_dictionary.pop('refined_constructor_list')

            # Accummulate various stats for the DB timestamp.
            db_timestamp['function_count'] += introspector_dictionary[
                'function_count']
            db_timestamp[
                'function_coverage_estimate'] += introspector_dictionary[
                    'functions_covered_estimate']

            all_header_files.append(project_info['all-header-files'])

        coverage_dictionary = project_info.get('coverage-data-dict', None)
        if coverage_dictionary is not None:
            # Accummulate various stats for the DB timestamp.
            db_timestamp["accummulated_lines_total"] += coverage_dictionary[
                'line_coverage']['count']
            db_timestamp["accummulated_lines_covered"] += coverage_dictionary[
                'line_coverage']['covered']

            # We include in project count if coverage is in here
            db_timestamp["project_count"] += 1

    # Return:
    # - all functions
    # - all constructors (maybe empty)
    # - a list of project timestamps
    # - the DB timestamp
    return function_dict, constructor_dict, project_timestamps, db_timestamp, all_header_files


def extend_db_timestamps(db_timestamp, output_directory):
    """Extends a DB timestamp .json file in output_directory with a given
    DB timestamp. If there is no DB timestamp .json file in the output
    directory then a DB timestamp file will be created.
    """
    existing_timestamps = []
    logging.info('Loading existing timestamps')
    if os.path.isfile(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP)):
        with open(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP),
                  'r') as f:
            try:
                existing_timestamps = orjson.loads(f.read())
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []
    logging.info('Number of existing timestamps: %d', len(existing_timestamps))
    to_add = True
    for ts in existing_timestamps:
        if ts['date'] == db_timestamp['date']:
            to_add = False
    if to_add:
        logging.info('Dumping new timestamps')
        existing_timestamps.append(db_timestamp)
        with open(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP),
                  'w') as f:
            json.dump(existing_timestamps, f)


def per_fuzzer_coverage_analysis(project_name: str,
                                 coverages: Dict[str, List[Tuple[int, str]]],
                                 lost_fuzzers):
    """Go through the recent coverage results and combine them into a short summary.
    Including an assessment if the fuzzer got worse over time.
    """

    # TODO This might not be a good metric when coverage is not meaningful,
    # for example for very small projects or projects that have low coverage
    # already. Though, this might not be super bad as we are taking a look
    # at per fuzzer coverage, which is should already be normalized to what
    # can be reached.
    # TODO What would be a good percentage to mark as coverage degradation,
    # taking 5% for now but should be observed, maybe per it should be
    # configurable per project as well.
    results = {}
    for ff, data in coverages.items():
        if len(data) > 0:
            values = [dd[0] for dd in data]
            dates = [dd[1] for dd in data]
            latest_date_with_value = next(dd[1] for dd in reversed(data)
                                          if dd[0] is not None)
            if latest_date_with_value is not None:
                report_url = oss_fuzz.get_fuzzer_code_coverage_summary_url(
                    project_name, latest_date_with_value.replace('-', ''), ff)
                report_url = report_url[:-len('summary.json')] + 'index.html'
            else:
                report_url = None
            max_cov = max(values[:-1], default=0)
            avg_cov = round(statistics.fmean(values), 2)
            current = values[-1]
            results[ff] = {
                'report_url': report_url,
                'report_date': latest_date_with_value,
                'coverages_values': values,
                'coverages_dates': dates,
                'max': max_cov,
                'avg': avg_cov,
                'current': current,
                'has_degraded':
                (max_cov - current) > FUZZER_COVERAGE_IS_DEGRADED,
                'got_lost': ff in lost_fuzzers,
            }
    return results


def calculate_recent_results(projects_with_new_results, timestamps,
                             num_days: int):
    """Analyse recent project data to detect possible degradations of fuzzer efficiency."""
    from collections import defaultdict

    data: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for pt in timestamps:
        project_name = pt['project_name']
        if project_name in projects_with_new_results:
            data[project_name][pt['date']] = pt

    results = {}
    for project_name, project_data in data.items():
        fuzzers_past = set()
        fuzzers_current: Set[str] = set()
        per_fuzzer_coverages = defaultdict(list)

        for do in (get_date_at_offset_as_str(ii)
                   for ii in range(-num_days, 0, 1)):
            try:
                date_data = project_data[do]
                per_fuzzer_coverage_data = date_data[
                    'per-fuzzer-coverage-data']

                fuzzers_past |= fuzzers_current
                fuzzers_current = set(per_fuzzer_coverage_data.keys())

                for ff, cov_data in per_fuzzer_coverage_data.items():
                    try:
                        perc = round(
                            100 * cov_data['covered'] / cov_data['count'], 2)
                    except:
                        perc = 0

                    per_fuzzer_coverages[ff].append((perc, do))
            except:
                continue

        fuzzer_diff = fuzzers_past - fuzzers_current
        per_fuzzer_coverages = per_fuzzer_coverage_analysis(
            project_name, per_fuzzer_coverages, fuzzer_diff)

        results[project_name] = per_fuzzer_coverages

    return results


def extend_db_json_files(project_timestamps, output_directory,
                         should_include_details):
    """Extends a set of DB .json files."""

    existing_timestamps = []
    logging.info('Loading existing timestamps')
    if os.path.isfile(
            os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP)):
        with open(
                os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP),
                'r') as f:
            try:
                existing_timestamps = orjson.loads(f.read())
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []
    logging.info('Number of existing timestamps: %d', len(existing_timestamps))

    logging.info('Creating timestamp mapping')
    have_added = False
    existing_timestamp_mapping = dict()

    for es in existing_timestamps:
        if es['project_name'] not in existing_timestamp_mapping:
            existing_timestamp_mapping[es['project_name']] = set()
        existing_timestamp_mapping[es['project_name']].add(es['date'])

    projects_with_new_results = set()
    for new_ts in project_timestamps:
        to_add = True

        if new_ts['project_name'] in existing_timestamp_mapping:
            if new_ts['date'] in existing_timestamp_mapping[
                    new_ts['project_name']]:
                to_add = False
        if to_add:
            existing_timestamps.append(new_ts)
            projects_with_new_results.add(new_ts['project_name'])
            have_added = True

    if FI_EXCLUDE_ALL_NON_MUSTS:
        # Filter existing timstamps to to only those in MUST_INCLUDES.
        kept_timestamps = []
        for ts in existing_timestamps:
            if ts['project_name'] in MUST_INCLUDES:
                kept_timestamps.append(ts)
        existing_timestamps = kept_timestamps

        # Also filter the current project results.
        kept_project_stamps = []
        for project_stamp in project_timestamps:
            if project_stamp['project_name'] in MUST_INCLUDES:
                kept_project_stamps.append(project_stamp)
        project_timestamps = kept_project_stamps

    if should_include_details:
        recent_results = calculate_recent_results(projects_with_new_results,
                                                  existing_timestamps,
                                                  NUM_RECENT_DAYS)
        # TODO these results might detect issues that should be communicated with
        # project maintainers. The best approach might be to load the
        # project_timestamps file (all-project-current.json)
        # separately and load recent results there and maybe issue warnings.
        for pt in project_timestamps:
            try:
                pt['recent_results'] = recent_results.get(pt['project_name'])
            except Exception as exc:
                logger.warning(
                    f'Could not get recent results for {pt["project_name"]}: {exc}'
                )
    else:
        recent_results = None

    logging.info('Dumping current project data')
    with open(os.path.join(output_directory, DB_JSON_ALL_CURRENT), 'w') as f:
        json.dump(project_timestamps, f)

    # Remove any light-introspector files because they should not be saved in the
    # timestamp file.
    for es2 in existing_timestamps:
        try:
            es2.pop('light-introspector', None)
        except:
            pass
    if have_added:
        logging.info('Dumping all timestamps')
        with open(
                os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP),
                'w') as f:
            f.write(orjson.dumps(existing_timestamps).decode('utf-8'))


def extend_func_db(function_dict, output_dir, target):
    # Loop for function list of all projects
    for proj in function_dict:
        json_path = os.path.join(output_dir, target.replace('{PROJ}', proj))

        # Process the new function list
        function_list = function_dict[proj]
        function_name_list = [function['name'] for function in function_list]

        # Retrieve existing function list for the target project
        if os.path.isfile(json_path):
            with open(json_path, 'r') as f:
                existing_function_list = json.load(f)
        else:
            existing_function_list = list()

        # Add new functions
        for function in existing_function_list:
            if function['name'] not in function_name_list:
                function_list.append(function)

        # Write to the function json for the target project
        with open(json_path, 'w') as f:
            json.dump(function_list, f)


def update_db_files(db_timestamp,
                    project_timestamps,
                    function_dict,
                    constructor_dict,
                    output_directory,
                    should_include_details,
                    all_header_files=None,
                    must_include_not_in_ossfuzz=None):
    logger.info(
        "Updating the database with DB snapshot. Number of functions in total: %d",
        db_timestamp['function_count'])
    if should_include_details:
        extend_func_db(function_dict, output_directory, DB_JSON_ALL_FUNCTIONS)
        extend_func_db(constructor_dict, output_directory,
                       DB_JSON_ALL_CONSTRUCTORS)

    if all_header_files is None:
        all_header_files = {}

    logging.info('Writing header files')
    with open('all-header-files.json', 'w') as f:
        f.write(json.dumps(all_header_files))

    logging.info('Extending DB json files')
    extend_db_json_files(project_timestamps, output_directory,
                         should_include_details)

    logging.info('Extending DB time stamps')
    extend_db_timestamps(db_timestamp, output_directory)

    if must_include_not_in_ossfuzz:
        to_dump = []
        for project in must_include_not_in_ossfuzz:
            for elem in MUST_INCLUDE_WITH_LANG:
                if elem['project'] == project:
                    to_dump.append(elem)

        with open('projects-not-in-oss-fuzz.json', 'w') as f:
            f.write(json.dumps(list(to_dump)))

    # Write a zip folder the values that make sense to save
    if should_include_details:
        logging.info('Writing ZIP archives')
        with zipfile.ZipFile('db-archive.zip', 'w') as zip_object:
            zip_object.write(os.path.join(output_directory,
                                          DB_JSON_DB_TIMESTAMP),
                             DB_JSON_DB_TIMESTAMP,
                             compress_type=zipfile.ZIP_DEFLATED)
            zip_object.write(os.path.join(output_directory,
                                          DB_JSON_ALL_PROJECT_TIMESTAMP),
                             DB_JSON_ALL_PROJECT_TIMESTAMP,
                             compress_type=zipfile.ZIP_DEFLATED)

        # Disable for now to avoid growing disk
        # ZIP the archived introspector reports
        #shutil.make_archive(DB_RAW_INTROSPECTOR_REPORTS, 'zip',
        #                    DB_RAW_INTROSPECTOR_REPORTS)

    # Disable for now to avoid growing disk
    # Cleanup DB_RAW_INTROSPECTOR_REPORTS
    #if os.path.isdir(DB_RAW_INTROSPECTOR_REPORTS):
    #    shutil.rmtree(DB_RAW_INTROSPECTOR_REPORTS)


def update_build_status(build_dict) -> None:
    """Writes the `build_dict` to the build status json file."""
    with open(DB_BUILD_STATUS_JSON, "w") as f:
        json.dump(build_dict, f)


def is_date_in_db(date: str, output_directory: str) -> bool:
    """Returns whether the date exists in the timestamp json file."""
    existing_timestamps = []
    if os.path.isfile(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP)):
        with open(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP),
                  'r') as f:
            try:
                existing_timestamps = json.load(f)
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []

    in_db = False
    for ts in existing_timestamps:
        if ts['date'] == date:
            in_db = True
    return in_db


def analyse_set_of_dates(dates, projects_to_analyse, output_directory,
                         force_creation, must_include_not_in_ossfuzz):
    """Performs analysis of all projects in the projects_to_analyse argument for
    the given set of dates. DB .json files are stored in output_directory.
    """
    idx = 1
    for date in dates:
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        logger.info("Analysing date %s -- [%d of %d] -- %s", date, idx,
                    len(dates), current_time)

        # Is this the last date to analyse?
        is_end = idx == len(dates)
        logger.info("Is this the last date: %s", is_end)

        # Increment counter. Must happen after our is_end check.
        idx += 1

        # If it's not the last date and we have cached data, use the cache.
        if not force_creation and is_end is False and is_date_in_db(
                date, output_directory):
            logger.info("Date already analysed, skipping")
            continue

        if force_creation:
            is_end = True

        function_dict, constructor_dict, project_timestamps, db_timestamp, all_header_files = analyse_list_of_projects(
            date, projects_to_analyse, should_include_details=is_end)
        logging.info('Updating DB files')
        update_db_files(
            db_timestamp,
            project_timestamps,
            function_dict,
            constructor_dict,
            output_directory,
            should_include_details=is_end,
            all_header_files=all_header_files,
            must_include_not_in_ossfuzz=must_include_not_in_ossfuzz)
        logging.info('Done updating DB files')


def extract_oss_fuzz_total_history(date_range, must_include):
    """Creates an OSS-Fuzz history project history"""

    logging.info('Cloning temporary OSS-Fuzz')
    of_tmp = 'tmp-oss-fuzz-clone'
    if os.path.isdir(of_tmp):
        shutil.rmtree(of_tmp)
    git_clone_project(constants.OSS_FUZZ_REPO, of_tmp)

    if not os.path.isdir(of_tmp):
        return
    oss_fuzz_project_count = []
    for date in date_range:
        logging.info('Date: %s', date)
        subprocess.check_call(
            'git checkout `git rev-list -n 1 --before="%s 13:00" master`' %
            (date),
            cwd=of_tmp,
            shell=True)
        if must_include:
            # count the projects we mean
            project_count = 0
            for project_name in os.listdir(os.path.join(of_tmp, 'projects')):
                if project_name in must_include:
                    project_count += 1
        else:
            # Count all projects
            project_count = len(os.listdir(os.path.join(of_tmp, 'projects')))
        oss_fuzz_project_count.append({
            'date': date,
            'project-count': project_count
        })

    if os.path.isdir(of_tmp):
        shutil.rmtree(of_tmp)
    with open('full-oss-fuzz-project-count.json', 'w') as f:
        f.write(json.dumps(oss_fuzz_project_count))


def get_date_at_offset_as_str(day_offset=-1) -> str:
    """Create string representing date based of offset from today."""
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


def cleanup(output_directory):
    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(output_directory, f)):
            os.remove(os.path.join(output_directory, f))


def copy_input_to_output(input_dir, output_dir):
    if input_dir == output_dir:
        return

    logger.info("The input dir: %s", input_dir)
    if not os.path.isdir(input_dir):
        raise Exception("No input directory, but specified")

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(input_dir, f)):
            shutil.copyfile(os.path.join(input_dir, f),
                            os.path.join(output_dir, f))


def prepare_output_folder(input_directory, output_directory):
    """Makes output folder ready for analysis."""

    # Copy input cache to output so analysis from current state.
    if input_directory is not None:
        copy_input_to_output(input_directory, output_directory)

    if not os.path.isdir(output_directory):
        os.mkdir(output_directory)


def extract_oss_fuzz_build_status(output_directory):
    """Extracts fuzz/coverage/introspector build status from OSS-Fuzz stats."""
    # Extract the build status of all OSS-Fuzz projects
    # Create a local clone of OSS-Fuzz. This is used for checking language of a project easily.
    oss_fuzz_local_clone = os.path.join(output_directory,
                                        constants.OSS_FUZZ_CLONE)
    if os.path.isdir(oss_fuzz_local_clone):
        shutil.rmtree(oss_fuzz_local_clone)
    git_clone_project(constants.OSS_FUZZ_REPO, oss_fuzz_local_clone)

    build_status_dict = oss_fuzz.get_projects_build_status()

    if FI_EXCLUDE_ALL_NON_MUSTS:
        new_build_status_dict = {}
        for bs, bs_val in build_status_dict.items():
            if bs in MUST_INCLUDES:
                new_build_status_dict[bs] = bs_val
        build_status_dict = new_build_status_dict

    update_build_status(build_status_dict)
    return build_status_dict


def create_date_range(day_offset, days_to_analyse) -> List[str]:
    """Gets list of strings representing dates to analyse."""
    date_range = []
    range_to_analyse = range(day_offset + days_to_analyse, day_offset, -1)
    for i in range_to_analyse:
        date_range.append(get_date_at_offset_as_str(i * -1))
    return date_range


def setup_github_cache() -> bool:
    """Prepares DB cache based on GitHub storage to avoid analysing
    full OSS-Fuzz history."""
    if os.path.isdir("github_cache"):
        shutil.rmtree("github_cache")

    git_clone_project(constants.OSS_FUZZ_GITHUB_BACKUP_REPO, "github_cache")
    if not os.path.isdir("github_cache"):
        return False
    db_zipfile = os.path.join("github_cache", "db-stamp.zip")
    if os.path.isfile(db_zipfile):
        with zipfile.ZipFile(db_zipfile, 'r') as zip_ref:
            zip_ref.extractall("github_cache")
        return True

    db_tarfile = os.path.join('github_cache', 'db-stamp.tar.xz')
    if os.path.isfile(db_tarfile):
        with tarfile.open(db_tarfile) as f:
            f.extractall('github_cache')
        return True

    return False


def setup_webapp_cache() -> None:
    """Prepares DB cache based on existing webapp to avoid analysing
    full OSS-Fuzz history."""
    logger.info("Getting the db archive")
    r = requests.get(INTROSPECTOR_WEBAPP_ZIP, stream=True, timeout=45)
    db_archive = zipfile.ZipFile(io.BytesIO(r.content))

    if os.path.isdir("extracted-db-archive"):
        shutil.rmtree("extracted-db-archive")
    os.mkdir("extracted-db-archive")

    db_archive.extractall("extracted-db-archive")
    logger.info("Extracted it all")

    # Copy over the files
    shutil.copyfile(os.path.join("extracted-db-archive", DB_JSON_DB_TIMESTAMP),
                    DB_JSON_DB_TIMESTAMP)
    shutil.copyfile(
        os.path.join("extracted-db-archive", DB_JSON_ALL_PROJECT_TIMESTAMP),
        DB_JSON_ALL_PROJECT_TIMESTAMP)

    # If we get to here it all went well.


def extract_must_includes(must_include_arg):
    global MUST_INCLUDE_WITH_LANG
    must_include = set()
    if os.path.isfile(must_include_arg):

        if must_include_arg.endswith('.json'):
            with open(must_include_arg, 'r') as f:
                contents = json.load(f)
            MUST_INCLUDE_WITH_LANG = contents
            for project in contents:
                must_include.add(project['project'])
        else:
            with open(must_include_arg, "r") as f:
                for line in f:
                    if line.strip():
                        must_include.add(line.strip())
    elif os.path.isdir(must_include_arg):
        # Convenient when reading OSS-Fuzz-gen benchmark folder
        for filename in os.listdir(must_include_arg):
            if filename.endswith(".yaml"):
                must_include.add(filename.replace(".yaml", ""))
    elif must_include_arg:
        for elem in must_include_arg.split(","):
            must_include.add(elem.strip())
    return must_include


def reduce_projects_to_analyse(projects_to_analyse, max_projects,
                               must_include):
    if max_projects <= 0:
        tmp_dictionary = dict()
        for k in projects_to_analyse:
            if must_include:
                for p in must_include:
                    if p in k:
                        tmp_dictionary[k] = projects_to_analyse[k]
            else:
                tmp_dictionary[k] = projects_to_analyse[k]
        projects_to_analyse = tmp_dictionary
    elif max_projects > 0 and len(projects_to_analyse) > max_projects:
        tmp_dictionary = dict()
        idx = 0
        for k in projects_to_analyse:
            for p in must_include:
                if p in k:
                    tmp_dictionary[k] = projects_to_analyse[k]

        for k in projects_to_analyse:
            if idx > max_projects:
                break
            tmp_dictionary[k] = projects_to_analyse[k]
            idx += 1
        projects_to_analyse = tmp_dictionary

    logger.info("Projects targeted in the DB creation")
    for project in projects_to_analyse:
        logger.info("- %s", project)
    return projects_to_analyse


def create_cache(use_webapp_cache, use_github_cache, input_directory,
                 output_directory):
    got_cache = False
    if use_webapp_cache:
        try:
            setup_webapp_cache()
            # If we got to here, that means the cache download went well.
            got_cache = True
        except:
            got_cache = False

    if use_github_cache and not got_cache:
        if setup_github_cache():
            input_directory = "github_cache"
        else:
            logger.info("Could not create Github cache")

    # Create folders we will
    prepare_output_folder(input_directory, output_directory)

    # Cleanup github
    if os.path.isdir("github_cache"):
        shutil.rmtree("github_cache")

    return input_directory


def get_dates_to_analyse(since_date, days_to_analyse, day_offset):
    if since_date is not None:
        start_date = datetime.datetime.strptime(since_date, "%d-%m-%Y").date()
        today = datetime.date.today()
        delta = today - start_date
        days_to_analyse = delta.days - 1
        day_offset = 0
    date_range = create_date_range(day_offset, days_to_analyse)

    return date_range


def create_local_db(oss_fuzz_path):
    """Creates a database based of local runs."""
    function_dict = {}
    constructor_dict = {}
    project_timestamps = []

    # Create a DB timestamp
    db_timestamp = {
        "date": '',
        "project_count": -1,
        "fuzzer_count": 0,
        "function_count": 0,
        "function_coverage_estimate": 0,
        "accummulated_lines_total": 0,
        "accummulated_lines_covered": 0,
    }

    oss_fuzz_build_path = os.path.join(oss_fuzz_path, 'build', 'out')

    projects_to_analyse = []
    for project_out in os.listdir(oss_fuzz_build_path):
        # Ensure we have an introspector folder
        introspector_out = os.path.join(oss_fuzz_build_path, project_out,
                                        'inspector')
        if not os.path.isdir(introspector_out):
            continue
        projects_to_analyse.append(project_out)

    analyses_dictionary = dict()
    for project in projects_to_analyse:
        # Get the data
        extract_local_project_data(project, oss_fuzz_path, analyses_dictionary)
    # Accummulate the data from all the projects.
    all_header_files = []
    for project_dict in analyses_dictionary.values():
        # Append project timestamp to the list of timestamps
        project_timestamp = project_dict['project_timestamp']
        project_timestamps.append(project_timestamp)
        db_timestamp['fuzzer_count'] += project_timestamp['fuzzer-count']

        # Extend all header files
        all_header_files.append(project_dict['all-header-files'])

        # Accummulate all function list and branch blockers
        introspector_dictionary = project_timestamp.get(
            'introspector-data', None)
        if introspector_dictionary is not None:
            proj = introspector_dictionary['project_name']
            # Functions
            if proj in function_dict:
                function_dict[proj].extend(
                    introspector_dictionary['refined_proj_list'])
            else:
                function_dict[proj] = introspector_dictionary[
                    'refined_proj_list']
            # Remove the function list because we don't want it anymore.
            introspector_dictionary.pop('refined_proj_list')

            # Constructors
            if proj in constructor_dict:
                constructor_dict[proj].extend(
                    introspector_dictionary['refined_constructor_list'])
            else:
                constructor_dict[proj] = introspector_dictionary[
                    'refined_constructor_list']
            # Remove the constructor list because we don't want it anymore.
            introspector_dictionary.pop('refined_constructor_list')

            # Accummulate various stats for the DB timestamp.
            db_timestamp['function_count'] += introspector_dictionary[
                'function_count']
            db_timestamp[
                'function_coverage_estimate'] += introspector_dictionary[
                    'functions_covered_estimate']

        coverage_dictionary = project_dict.get('coverage-data-dict', None)
        if coverage_dictionary is not None:
            # Accummulate various stats for the DB timestamp.
            db_timestamp["accummulated_lines_total"] += coverage_dictionary[
                'line_coverage']['count']
            db_timestamp["accummulated_lines_covered"] += coverage_dictionary[
                'line_coverage']['covered']

            # We include in project count if coverage is in here
            db_timestamp["project_count"] += 1

    update_db_files(db_timestamp,
                    project_timestamps,
                    function_dict,
                    constructor_dict,
                    os.getcwd(),
                    should_include_details=True,
                    all_header_files=all_header_files)


def create_db(max_projects, days_to_analyse, output_directory, input_directory,
              day_offset, to_cleanup, since_date, use_github_cache,
              use_webapp_cache, force_creation, includes):
    must_include = extract_must_includes(includes)

    for must_include_project in must_include:
        MUST_INCLUDES.add(must_include_project)
    # Set up cache and input/output directory
    input_directory = create_cache(use_webapp_cache, use_github_cache,
                                   input_directory, output_directory)

    # Get latest build statuses from OSS-Fuzz and use this to guide which
    # projects to analyze.
    projects_list_build_status = extract_oss_fuzz_build_status(
        output_directory)
    projects_to_analyse = dict()
    for k, v in projects_list_build_status.items():
        projects_to_analyse[k] = v

    must_includes_not_in_ossfuzz = set()
    for project in MUST_INCLUDES:
        if project not in projects_to_analyse:
            logger.info('Project not in OSS-Fuzz: %s', project)
            must_includes_not_in_ossfuzz.add(project)

    # Reduce the amount of projects if needed.
    projects_to_analyse = reduce_projects_to_analyse(projects_to_analyse,
                                                     max_projects,
                                                     must_include)

    if to_cleanup:
        cleanup(output_directory)

    date_range = get_dates_to_analyse(since_date, days_to_analyse, day_offset)
    extract_oss_fuzz_total_history(date_range, must_include)

    logger.info("Creating a DB with the specifications:")
    logger.info("- Date range: [%s : %s]", str(date_range[0]),
                str(date_range[-1]))
    logger.info("- Total of %d projects to analyse", len(projects_to_analyse))
    if input_directory is not None:
        logger.info("- Extending upon the DB in %s", str(input_directory))
    else:
        logger.info("-Creating the DB from scratch")

    logger.info("Starting analysis of max %d projects",
                len(projects_to_analyse))

    analyse_set_of_dates(date_range, projects_to_analyse, output_directory,
                         force_creation, must_includes_not_in_ossfuzz)


def get_cmdline_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-projects",
        help=
        "The maximum number of projects to include in the DB. -1 will extract data about all projects.",
        default=-1,
        type=int)
    parser.add_argument("--days-to-analyse",
                        help="The number of days to analyse",
                        default=1,
                        type=int)
    parser.add_argument("--output-dir",
                        help="Output directory for the produced .json files",
                        default=os.getcwd())
    parser.add_argument("--input-dir",
                        help="Input directory with existing .json files",
                        default=None)
    parser.add_argument("--base-offset",
                        help="Day offset",
                        type=int,
                        default=1)
    parser.add_argument(
        "--since-date",
        help="Include data from this date an onwards, in format \"d-m-y\"",
        default=None)
    parser.add_argument(
        "--includes",
        help=
        "File with names of projects (line separated) that must be included in the DB",
        default='')
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--use_gh_cache", action="store_false")
    parser.add_argument("--use_webapp_cache", action="store_true")
    parser.add_argument("--force-creation", action="store_true")
    parser.add_argument(
        "--local-oss-fuzz",
        help=
        'Sets local OSS-Fuzz directory. Forces DB to be created from this.',
        default=None)
    return parser


def main():
    parser = get_cmdline_parser()
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO,
                            format=('%(asctime)s.%(msecs)03d %(levelname)s '
                                    '%(module)s - %(funcName)s: %(message)s'))

    if args.local_oss_fuzz:
        logging.info('Using local version of OSS-Fuzz.')
        create_local_db(args.local_oss_fuzz)
    else:
        create_db(args.max_projects, args.days_to_analyse, args.output_dir,
                  args.input_dir, args.base_offset, args.cleanup,
                  args.since_date, args.use_gh_cache, args.use_webapp_cache,
                  args.force_creation, args.includes)


if __name__ == "__main__":
    main()
