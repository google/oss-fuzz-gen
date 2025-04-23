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
"""Auto OSS-Fuzz generator from inside OSS-Fuzz containers."""

import argparse
import json
import logging
import os
import shutil
import subprocess
from typing import List, Tuple

import build_script_generator
import file_utils as utils
import templates
import yaml

INTROSPECTOR_OSS_FUZZ_DIR = '/src/inspector'

INTROSPECTOR_ALL_FUNCTIONS_FILE = 'all-fuzz-introspector-functions.json'

LLM_MODEL = ''

FUZZER_PRE_HEADERS = '''#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
'''

SECONDS_TO_RUN_HARNESS = 20

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] '
           ': %(funcName)s: %(message)s')


def setup_model(model: str):
  global LLM_MODEL
  LLM_MODEL = model


class Test:
  """Holder of data about tests used by a repository."""

  def __init__(self, test_path, test_content):
    self.test_path = test_path
    self.test_content = test_content


def get_all_functions_in_project(introspection_files_found):
  all_functions_in_project = []
  for fi_yaml_file in introspection_files_found:
    with open(fi_yaml_file, 'r') as file:
      yaml_content = yaml.safe_load(file)
    for elem in yaml_content['All functions']['Elements']:
      all_functions_in_project.append(elem)

  return all_functions_in_project


##################################################
#### Heuristics for auto generating harnesses ####
##################################################


def get_all_header_files(all_files: List[str]) -> List[str]:
  all_header_files = []
  to_avoids = ['stdlib.h', 'stdio.h', 'unistd.h']
  for yaml_file in all_files:
    if yaml_file.endswith('.h'):
      header_basename = os.path.basename(yaml_file)
      if header_basename in to_avoids:
        continue
      all_header_files.append(yaml_file)
  return all_header_files


def get_all_introspector_files(target_dir):
  all_files = utils.get_all_files_in_path(target_dir)
  introspection_files_found = []
  for yaml_file in all_files:
    if 'allFunctionsWithMain' in yaml_file:
      #print(yaml_file)
      introspection_files_found.append(yaml_file)
    elif 'fuzzerLogFile-' in yaml_file and yaml_file.endswith('.yaml'):
      introspection_files_found.append(yaml_file)
  return introspection_files_found


def build_empty_fuzzers(build_workers, language) -> None:
  """Run build scripts against an empty fuzzer harness."""
  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.

  # For each of the auto generated build scripts try to link
  # the resulting static libraries against an empty fuzzer.
  fuzz_compiler, _, empty_fuzzer_file, fuzz_template = (
      utils.get_language_defaults(language))
  for test_dir, build_worker in build_workers:
    logger.info('Test dir: %s :: %s', test_dir,
                str(build_worker.executable_files_build['refined-static-libs']))

    if not build_worker.executable_files_build['refined-static-libs']:
      continue

    logger.info('Trying to link in an empty fuzzer')

    #empty_fuzzer_file = '/src/empty-fuzzer.cpp'
    with open(empty_fuzzer_file, 'w') as f:
      f.write(fuzz_template)

    # Try to link the fuzzer to the static libs
    cmd = [
        fuzz_compiler, '-fsanitize=fuzzer', '-fsanitize=address',
        empty_fuzzer_file
    ]
    for refined_static_lib in build_worker.executable_files_build[
        'refined-static-libs']:
      cmd.append(os.path.join(test_dir, refined_static_lib))

    logger.info('Command [%s]', ' '.join(cmd))
    try:
      subprocess.check_call(' '.join(cmd), shell=True)
      base_fuzz_build = True
    except subprocess.CalledProcessError:
      base_fuzz_build = False

    logger.info('Base fuzz build: %s', str(base_fuzz_build))
    build_worker.base_fuzz_build = base_fuzz_build


def refine_static_libs(build_results) -> None:
  """Returns a list of static libraries with substitution of common gtest
  libraries, which should not be linked in the fuzzer builds."""
  for test_dir in build_results:
    refined_static_list = []
    libs_to_avoid = {
        'libgtest.a', 'libgmock.a', 'libgmock_main.a', 'libgtest_main.a'
    }
    build_worker = build_results[test_dir]
    static_libs = build_worker.executable_files_build['static-libs']
    for static_lib in static_libs:
      if any(
          os.path.basename(static_lib) in lib_to_avoid
          for lib_to_avoid in libs_to_avoid):
        continue
      refined_static_list.append(static_lib)
    build_worker.executable_files_build[
        'refined-static-libs'] = refined_static_list


def run_introspector_on_dir(build_worker, test_dir,
                            language) -> Tuple[bool, List[str]]:
  """Runs Fuzz Introspector on a target directory with the ability
    to analyse code without having fuzzers (FUZZ_INTROSPECTOR_AUTO_FUZZ=1).

    This is done by running the bbuild script that succeeded using introspector
    sanitizer from OSS-Fuzz, where introspector will collect data form any
    executable linked during the vanilla build.

    This is done by way of the OSS-Fuzz `compile` command and by setting
    the environment appropriately before running this command.
    """
  introspector_vanilla_build_script = build_worker.build_script
  (fuzz_compiler, fuzz_flags, empty_fuzzer_file,
   fuzz_template) = utils.get_language_defaults(language)

  with open(empty_fuzzer_file, 'w') as f:
    f.write(fuzz_template)

  # Try to link the fuzzer to the static libs
  fuzzer_build_cmd = [
      fuzz_compiler, fuzz_flags, '$LIB_FUZZING_ENGINE', empty_fuzzer_file
  ]
  fuzzer_build_cmd.append('-Wl,--allow-multiple-definition')
  for refined_static_lib in build_worker.executable_files_build[
      'refined-static-libs']:
    fuzzer_build_cmd.append('-Wl,--whole-archive')
    fuzzer_build_cmd.append(os.path.join(test_dir, refined_static_lib))
  fuzzer_build_cmd.append('-Wl,--no-whole-archive')

  fuzzer_build_cmd.append('-o /src/compiled_binary')

  introspector_vanilla_build_script += '\n'
  introspector_vanilla_build_script += ' '.join(fuzzer_build_cmd)

  with open('/src/build.sh', 'w') as bs:
    bs.write(introspector_vanilla_build_script)

  if os.path.isfile('/src/compiled_binary'):
    os.remove('/src/compiled_binary')

  modified_env = os.environ
  modified_env['SANITIZER'] = 'introspector'
  modified_env['FUZZ_INTROSPECTOR_AUTO_FUZZ'] = '1'
  modified_env['PROJECT_NAME'] = 'auto-fuzz-proj'
  modified_env['FUZZINTRO_OUTDIR'] = test_dir

  # Disable FI light because we want to make sure we can compile as well.
  modified_env['FI_DISABLE_LIGHT'] = "1"

  try:
    subprocess.check_call('compile',
                          shell=True,
                          env=modified_env,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    build_returned_error = False
  except subprocess.CalledProcessError:
    build_returned_error = True

  if not os.path.isfile('/src/compiled_binary'):
    build_returned_error = True

  logger.info('Introspector build: %s', str(build_returned_error))
  return build_returned_error, fuzzer_build_cmd


def create_clean_oss_fuzz_from_empty(github_repo: str, build_worker,
                                     language: str, test_dir) -> None:
  """Converts a successful empty fuzzer build into an OSS-Fuzz project."""

  # Save the results
  nidx = 0
  oss_fuzz_folder = f'/out/empty-build-{nidx}'
  while os.path.isdir(oss_fuzz_folder):
    nidx += 1
    oss_fuzz_folder = f'/out/empty-build-{nidx}'

  os.makedirs(oss_fuzz_folder)

  introspector_vanilla_build_script = build_worker.build_script
  (fuzz_compiler, fuzz_flags, empty_fuzzer_file,
   fuzz_template) = utils.get_language_defaults(language)

  # Write empty fuzzer
  with open(os.path.join(oss_fuzz_folder, os.path.basename(empty_fuzzer_file)),
            'w') as f:
    f.write(fuzz_template)

  # Try to link the fuzzer to the static libs
  fuzzer_build_cmd = [
      fuzz_compiler, fuzz_flags, '$LIB_FUZZING_ENGINE', empty_fuzzer_file
  ]
  fuzzer_build_cmd.append('-Wl,--allow-multiple-definition')
  for refined_static_lib in build_worker.executable_files_build[
      'refined-static-libs']:
    fuzzer_build_cmd.append('-Wl,--whole-archive')
    fuzzer_build_cmd.append(os.path.join(test_dir, refined_static_lib))

  fuzzer_build_cmd.append('-Wl,--no-whole-archive')

  # Add inclusion of header file paths. This is anticipating any harnesses
  # will make an effort to include relevant header files.
  all_header_files = get_all_header_files(utils.get_all_files_in_path(test_dir))
  paths_to_include = set()
  for header_file in all_header_files:
    if not header_file.startswith('/src/'):
      header_file = '/src/' + header_file
    if '/test/' in header_file:
      continue
    if 'googletest' in header_file:
      continue

    path_to_include = '/'.join(header_file.split('/')[:-1])
    paths_to_include.add(path_to_include)
  for path_to_include in paths_to_include:
    logger.info('Path to include: %s', path_to_include)
    fuzzer_build_cmd.append(f'-I{path_to_include}')

  introspector_vanilla_build_script += '\n'
  introspector_vanilla_build_script += ' '.join(fuzzer_build_cmd)

  #with open(os.path.join(oss_fuzz_folder, 'build.sh'), 'w') as bs:
  #  bs.write(introspector_vanilla_build_script)

  # Project yaml
  project_yaml = {
      'homepage': github_repo,
      'language': language,
      'primary_contact': 'add_your_email@here.com',
      'main_repo': github_repo
  }
  with open(os.path.join(oss_fuzz_folder, 'project.yaml'), 'w') as project_out:
    yaml.dump(project_yaml, project_out)

  # Create Dockerfile
  project_repo_dir = github_repo.split('/')[-1]
  additional_packages = build_worker.build_suggestion.list_of_required_packages
  dockerfile = templates.CLEAN_OSS_FUZZ_DOCKER.format(
      repo_url=github_repo,
      project_repo_dir=project_repo_dir,
      additional_packages=' '.join(additional_packages),
      fuzzer_dir='$SRC/fuzzers/')
  with open(os.path.join(oss_fuzz_folder, 'Dockerfile'), 'w') as docker_out:
    docker_out.write(dockerfile)

  logger.info('Build script:')
  logger.info(introspector_vanilla_build_script)
  logger.info('-' * 45)

  # Build file
  clean_build_content = convert_test_build_to_clean_build(
      introspector_vanilla_build_script, project_repo_dir)

  with open(os.path.join(oss_fuzz_folder, 'build.sh'), 'w') as f:
    f.write(clean_build_content)


def create_clean_oss_fuzz_from_success(github_repo: str, out_dir: str,
                                       pkgs: List[str], language: str) -> None:
  """Converts a successful out dir into a working OSS-Fuzz project."""
  oss_fuzz_folder = os.path.join(out_dir, 'oss-fuzz-project')
  os.makedirs(oss_fuzz_folder)

  # Project yaml
  project_yaml = {
      'homepage': github_repo,
      'language': language,
      'primary_contact': 'add_your_email@here.com',
      'main_repo': github_repo
  }
  with open(os.path.join(oss_fuzz_folder, 'project.yaml'), 'w') as project_out:
    yaml.dump(project_yaml, project_out)

  # Copy fuzzer
  _, _, fuzzer_target_file, _ = utils.get_language_defaults(language)
  shutil.copy(
      os.path.join(out_dir, os.path.basename(fuzzer_target_file)),
      os.path.join(oss_fuzz_folder,
                   os.path.basename(fuzzer_target_file).replace('empty-', '')))

  # Create Dockerfile
  project_repo_dir = github_repo.split('/')[-1]
  dockerfile = templates.CLEAN_OSS_FUZZ_DOCKER.format(
      repo_url=github_repo,
      project_repo_dir=project_repo_dir,
      additional_packages=' '.join(pkgs),
      fuzzer_dir='$SRC/fuzzers/')
  with open(os.path.join(oss_fuzz_folder, 'Dockerfile'), 'w') as docker_out:
    docker_out.write(dockerfile)

  # Build file
  with open(os.path.join(out_dir, 'build.sh'), 'r') as f:
    build_content = f.read()

  clean_build_content = convert_test_build_to_clean_build(
      build_content, project_repo_dir)

  with open(os.path.join(oss_fuzz_folder, 'build.sh'), 'w') as f:
    f.write(clean_build_content)


def create_clean_clusterfuzz_lite_from_success(github_repo: str, out_dir: str,
                                               pkgs: List[str],
                                               language: str) -> None:
  """Converts a successful out dir into a working ClusterFuzzLite project."""
  cflite_folder = os.path.join(out_dir, 'clusterfuzz-lite-project')
  os.makedirs(cflite_folder)

  # Project yaml
  project_yaml = {
      'language': language,
  }
  with open(os.path.join(cflite_folder, 'project.yaml'), 'w') as project_out:
    yaml.dump(project_yaml, project_out)

  # Copy fuzzer
  _, _, fuzzer_target_file, _ = utils.get_language_defaults(language)
  shutil.copy(
      os.path.join(out_dir, os.path.basename(fuzzer_target_file)),
      os.path.join(cflite_folder,
                   os.path.basename(fuzzer_target_file).replace('empty-', '')))

  # Create Dockerfile
  project_repo_dir = github_repo.split('/')[-1]
  dockerfile = templates.CLEAN_DOCKER_CFLITE.format(
      project_repo_dir=project_repo_dir, additional_packages=' '.join(pkgs))
  with open(os.path.join(cflite_folder, 'Dockerfile'), 'w') as docker_out:
    docker_out.write(dockerfile)

  # Build file
  with open(os.path.join(out_dir, 'build.sh'), 'r') as f:
    build_content = f.read()

  clean_build_content = convert_test_build_to_clean_build(
      build_content, project_repo_dir)

  with open(os.path.join(cflite_folder, 'build.sh'), 'w') as f:
    f.write(clean_build_content)

  with open(os.path.join(cflite_folder, 'cflite_pr.yml'), 'w') as f:
    f.write(templates.CFLITE_TEMPLATE)


def convert_fuzz_build_line_to_loop(clean_build_content: str,
                                    original_build_folder: str,
                                    project_repo_dir: str) -> str:
  """Adjust fuzz building script so that harnesses are build in a loop
  iterating $SRC/fuzzers/*. The goal of this is to make it easier to add
  additional harnesses that will also get build.
  """
  split_lines = clean_build_content.split('\n')
  target_line_idx = -1
  for idx, tmp_line in enumerate(split_lines):
    if '/src/generated-fuzzer' in tmp_line or '/src/empty-fuzzer' in tmp_line:
      target_line_idx = idx
      break
  if target_line_idx == -1:
    raise RuntimeError('Did not find harness build command.')

  wrapper_script = '''for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  LINE_TO_SUBSTITUTE
done'''
  target_line = split_lines[target_line_idx]

  # Make adjustments to the harness build command:
  # 1) Output fuzzers to $OUT/ instead of /src/generated-fuzzer
  # 2) Name fuzzer baesd on bash variable instead of 'empty-fuzzer'
  # 3) Use '$SRC/' instead of '/src/'
  # 4) Rewrite file paths from test build directory to cloned directory, to
  # adjust e.g. library and include paths.
  target_line = target_line.replace(
      '/src/generated-fuzzer', '$OUT/${fuzzer_target}').replace(
          '/src/empty-fuzzer.cpp',
          '${fuzzer}').replace('/src/empty-fuzzer.c', '${fuzzer}').replace(
              '/src/', '$SRC/').replace(original_build_folder, project_repo_dir)

  if '$OUT/${fuzzer_target}' not in target_line:
    target_line += ' -o $OUT/${fuzzer_target}'

  wrapper_script = wrapper_script.replace('LINE_TO_SUBSTITUTE', target_line)
  split_lines[target_line_idx] = wrapper_script
  return '\n'.join(split_lines)


def convert_test_build_to_clean_build(test_build_script: str,
                                      project_repo_dir: str) -> str:
  """Rewrites a build.sh used during testing to a proper OSS-Fuzz build.sh."""
  split_build_content = test_build_script.split('\n')

  # Extract the test folder name
  original_build_folder = split_build_content[1].split('/')[-1]

  # Remove the lines used in the testing build script to navigate test folders.
  clean_build_content_lines = '\n'.join(split_build_content[:1] +
                                        split_build_content[4:])

  clean_build_content = convert_fuzz_build_line_to_loop(
      clean_build_content_lines, original_build_folder, project_repo_dir)
  return clean_build_content


def append_to_report(outdir, msg):
  if not os.path.isdir(outdir):
    os.mkdir(outdir)
  report_path = os.path.join(outdir, 'report.txt')
  with open(report_path, 'a+') as f:
    f.write(msg + '\n')


def load_introspector_report():
  """Extract introspector as python dictionary from local run."""
  if not os.path.isfile(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR,
                                     'summary.json')):
    return None
  with open(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, 'summary.json'), 'r') as f:
    summary_report = json.loads(f.read())

  # Get all functions folder
  if not os.path.isfile(
      os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, INTROSPECTOR_ALL_FUNCTIONS_FILE)):
    return None
  with open(
      os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, INTROSPECTOR_ALL_FUNCTIONS_FILE),
      'r') as f:
    all_functions_list = json.loads(f.read())

  summary_report['MergedProjectProfile']['all-functions'] = all_functions_list
  return summary_report


def auto_generate(github_url, disable_testing_build_scripts=False, outdir=''):
  """Generates build script and fuzzer harnesses for a GitHub repository."""
  target_source_path = os.path.join(os.getcwd(), github_url.split('/')[-1])
  dst_folder = github_url.split('/')[-1]

  # clone the base project into a dedicated folder
  if not os.path.isdir(target_source_path):
    subprocess.check_call(
        f'git clone --recurse-submodules {github_url} {dst_folder}', shell=True)

  # Stage 1: Build script generation
  language = utils.determine_project_language(target_source_path)
  logger.info('Target language: %s', language)
  append_to_report(outdir, f'Target language: {language}')

  # record the path
  logger.info('[+] Extracting build scripts statically')
  all_build_scripts: List[Tuple[
      str, str, build_script_generator.
      AutoBuildContainer]] = build_script_generator.extract_build_suggestions(
          target_source_path, 'test-fuzz-build-')

  # Check each of the build scripts.
  logger.info('[+] Testing build suggestions')
  build_results = build_script_generator.raw_build_evaluation(all_build_scripts)
  logger.info('Checking results of %d build generators', len(build_results))

  if disable_testing_build_scripts:
    logger.info('disabling testing build scripts')
    return

  for test_dir, build_worker in build_results.items():
    build_heuristic = build_worker.build_suggestion.heuristic_id
    static_libs = build_worker.executable_files_build['static-libs']

    append_to_report(
        outdir,
        f'build success: {build_heuristic} :: {test_dir} :: {static_libs}')
    logger.info('%s : %s : %s', build_heuristic, test_dir, static_libs)

  # For each of the auto generated build scripts identify the
  # static libraries resulting from the build.
  refine_static_libs(build_results)

  refined_builds = []
  b_idx = 0
  for test_dir, build_worker in build_results.items():
    if len(build_worker.executable_files_build) > 1:
      for ref_lib in build_worker.executable_files_build['refined-static-libs']:
        b_idx += 1
        new_worker = build_script_generator.BuildWorker(
            build_worker.build_suggestion, build_worker.build_script,
            build_worker.build_directory,
            build_worker.executable_files_build.copy())
        new_worker.build_suggestion.heuristic_id = new_worker.build_suggestion.heuristic_id + '-%d' % (
            b_idx)
        new_worker.executable_files_build['refined-static-libs'] = [ref_lib]
        refined_builds.append((test_dir, new_worker))
    refined_builds.append((test_dir, build_worker))

  build_results = refined_builds

  logger.info('logging builds')
  for test_dir, build_worker in build_results:
    logger.info('Sample:')
    logger.info(json.dumps(build_worker.executable_files_build))
  logger.info('------------------------')

  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.
  build_empty_fuzzers(build_results, language)

  # Stage 3: Harness generation and harness testing.
  # We now know for which versions we can generate a base fuzzer.
  # Continue by runnig an introspector build using the auto-generated
  # build scripts but fuzz introspector as the sanitier. The introspector
  # build will analyze all code build in the project, meaning we will
  # extract build data for code linked in e.g. samples and more during
  # the build. The consequence is we will have a lot more data than if
  # we only were to build the base fuzzer using introspector builds.
  # Then, proceed to use the generated program analysis data as arguments
  # to heuristics which will generate fuzzers.
  # We need to run introspector per build, because we're essentially not
  # sure if the produced binary files are the same. We could maybe optimize
  # this to check if there are differences in build output.
  logger.info('Going through %d build results to generate fuzzers',
              len(build_results))

  for test_dir, build_worker in build_results:
    logger.info('Checking build heuristic: %s',
                build_worker.build_suggestion.heuristic_id)

    # Skip if build suggestion did not work with an empty fuzzer.
    if not build_worker.base_fuzz_build:
      logger.info('Build failed, skipping')
      continue

    # Run Fuzz Introspector on the target
    logger.info('Running introspector build')
    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      shutil.rmtree(INTROSPECTOR_OSS_FUZZ_DIR)

    build_returned_error, _ = run_introspector_on_dir(build_worker, test_dir,
                                                      language)

    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      logger.info('Introspector build success')
    else:
      logger.info('Failed to get introspector results')

    if build_returned_error:
      logger.info(
          'Introspector build returned error, but light version worked.')
      continue

    # Identify the relevant functions
    introspector_report = load_introspector_report()
    if introspector_report is None:
      continue

    func_count = len(
        introspector_report['MergedProjectProfile']['all-functions'])
    logger.info('Found a total of %d functions.', func_count)
    append_to_report(outdir, 'Introspector analysis done')

    logger.info('Test dir: %s', str(test_dir))

    append_to_report(outdir, f'Total functions in {test_dir} : {func_count}')

    create_clean_oss_fuzz_from_empty(github_url, build_worker, language,
                                     test_dir)


def parse_commandline():
  """Commandline parser."""
  parser = argparse.ArgumentParser()
  parser.add_argument('repo', help='Github url of target')
  parser.add_argument('--disable-build-test',
                      action='store_true',
                      help='disables')
  parser.add_argument('--out', '-o', help='Directory to store successful runs')
  parser.add_argument('--model',
                      '-m',
                      help='Model to use for auto generation',
                      type=str)
  return parser


def setup_logging():
  logging.basicConfig(level=logging.INFO, format=LOG_FMT)


def main():
  parser = parse_commandline()
  args = parser.parse_args()
  setup_logging()

  setup_model(args.model)

  append_to_report(args.out, f'Analysing: {args.repo}')

  auto_generate(args.repo, args.disable_build_test, args.out)


if __name__ == '__main__':
  main()
