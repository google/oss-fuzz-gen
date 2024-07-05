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
"""Utilities for generating builder scripts for a GitHub repository."""

import logging
import os
import shutil
import subprocess
from abc import abstractmethod
from typing import Any, Dict, Iterator, List, Tuple

import manager

logger = logging.getLogger(name=__name__)


############################################################
#### Logic for auto building a given source code folder ####
############################################################
class AutoBuildContainer:

  def __init__(self):
    self.list_of_commands = []
    self.heuristic_id = ''


class AutoBuildBase:
  """Base class for auto builders."""

  def __init__(self):
    self.matches_found = {}

  @abstractmethod
  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    """Yields AutoBuildContainer objects."""

  def match_files(self, file_list):
    """Matches files needed for the build heuristic."""
    for fi in file_list:
      base_file = os.path.basename(fi)
      for key, val in self.matches_found.items():
        if base_file == key:
          val.append(fi)

  def is_matched(self):
    """Returns True if the build heuristic found matching files."""
    for found_matches in self.matches_found.values():
      if len(found_matches) > 0:
        return True
    return False


class PureCFileCompiler(AutoBuildBase):
  """Builder for compiling .c files direcetly in root repo dir."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        '.c': [],
    }

  def match_files(self, file_list):
    """Matches files needed for the build heuristic."""
    for fi in file_list:
      for key, val in self.matches_found.items():
        if fi.endswith(key) and 'test' not in fi and 'example' not in fi:
          logger.info('Adding %s', fi)
          # Remove the first folder as that is "this" dir.
          path_to_add = '/'.join(fi.split('/')[1:])
          val.append(path_to_add)

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    build_container.list_of_commands = [
        '''for file in "%s"; do
  $CC $CFLAGS -c ${file}
done

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o
''' % (' '.join(self.matches_found['.c']))
    ]
    build_container.heuristic_id = self.name + '1'
    logger.info(build_container.list_of_commands[0])
    yield build_container

  @property
  def name(self):
    return 'pureCFileCompiler'


class PureCFileCompilerFind(AutoBuildBase):
  """Builder for compiling .c files direcetly in root repo dir, using find."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        '.c': [],
    }

  def match_files(self, file_list):
    """Matches files needed for the build heuristic."""
    for fi in file_list:
      for key, val in self.matches_found.items():
        if fi.endswith(key):
          val.append(fi)

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    build_container.list_of_commands = [
        '''find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \\;
find . -name "*.o" -exec cp {} . \\;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o
'''
    ]
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'pureCFileCompilerFind'


class PureMakefileScanner(AutoBuildBase):
  """Auto builder for pure Makefile projects, only relying on "make"."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    build_container.list_of_commands = ['make']
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'make'


class PureMakefileScannerWithPThread(AutoBuildBase):
  """Auto builder for pure Makefile projects, only relying on "make"."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    build_container.list_of_commands = [
        'export CXXFLAGS="${CXXFLAGS} -lpthread"', 'make'
    ]
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'make'


class PureMakefileScannerWithSubstitutions(AutoBuildBase):
  """Auto builder for pure Makefile projects with substitions."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    # The following substitutes varioues patterns of overwriting of compilers
    # which happens in some build files. Patterns of Werror are also suppressed
    # by converting them to Wno-error.
    build_container.list_of_commands = [
        'sed -i \'s/-Werror/-Wno-error/g\' ./Makefile',
        'sed -i \'s/CC=/#CC=/g\' ./Makefile',
        'sed -i \'s/CXX=/#CXX=/g\' ./Makefile',
        'sed -i \'s/CC =/#CC=/g\' ./Makefile',
        'sed -i \'s/CXX =/#CXX=/g\' ./Makefile', 'make V=1 || true'
    ]
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'makeWithSubstitutions'


class AutoRefConfScanner(AutoBuildBase):
  """Auto-builder for patterns of "autoreconf fi; ./configure' make"""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile.am': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ['autoreconf -fi', './configure', 'make']
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'autogen'


class RawMake(AutoBuildBase):
  """Similar to PureMake but also adds option for "make test". This is useful
  to trigger more Fuzz Introspector analysis in the project."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ['make']
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

    build_container2 = AutoBuildContainer()
    build_container2.list_of_commands = cmds_to_exec_from_root + ['make test']
    build_container2.heuristic_id = self.name + '1'
    yield build_container2

  @property
  def name(self):
    return 'RawMake'


class AutogenScanner(AutoBuildBase):
  """Auto builder for projects relying on "autoconf; autoheader."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ['autoconf', 'autoheader', './configure', 'make']
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'autogen'


class AutogenScannerSH(AutoBuildBase):
  """Auto builder for projects relying on "autogen.sh; autoconf; autoheader."""

  def __init__(self):
    super().__init__()
    self.matches_found = {'configure.ac': [], 'autogen.sh': []}

  def steps_to_build(self):
    cmds_to_exec_from_root = ['./autogen.sh', './configure', 'make']
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'autogen20'


class BootstrapScanner(AutoBuildBase):
  """Auto builder for projects that rely on bootstrap.sh; configure; make."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'bootstrap.sh': [],
        'Makefile.am': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ['./bootstrap.sh', './configure', 'make']
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'bootstrap-make'


class AutogenConfScanner(AutoBuildBase):
  """Auto builder for projects relying on "autoconf; autoheader."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ['./configure', 'make']
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'autogen-ConfMake'


class CMakeScannerOptsParser(AutoBuildBase):
  """Calls cmake to extract options from the CMakeLists.txt file of a project
  and creates a build string where all BOOL values are set to OFF except those
  with 'STATIC' in the name."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'CMakeLists.txt': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = [
        'mkdir fuzz-build',
        'cd fuzz-build',
        (f'cmake -DCMAKE_VERBOSE_MAKEFILE=ON {self.cmake_string} '
         '-DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC ../'),
        'make V=1 || true',
    ]
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'autogen-ConfMakeOpt'

  def match_files(self, file_list: List[str]) -> None:
    """Find CMakeLists.txt files and extract a string of the CMake options
    that have all BOOL options set to OFF except for those with "STATIC" in the
    name."""
    for fi in file_list:
      # Focus on top dir
      if fi.count('/') > 1:
        continue
      base_file = os.path.basename(fi)
      for key, matches in self.matches_found.items():
        if base_file == key:
          # Move directory
          current_dir = os.getcwd()
          cmake_base_dir = '/'.join(fi.split('/')[:-1])
          tmp_idx = 0
          tmp_dir = os.path.join(cmake_base_dir, f'temp-build-{tmp_idx}')
          while os.path.isdir(tmp_dir):
            tmp_idx += 1
            tmp_dir = os.path.join(cmake_base_dir, f'temp-build-{tmp_idx}')

          os.mkdir(tmp_dir)
          os.chdir(tmp_dir)
          extracted_string = self.extract_defensive_options()
          if extracted_string:
            matches.append(fi)
            self.cmake_string = extracted_string
          os.chdir(current_dir)
          shutil.rmtree(tmp_dir)

  def extract_cmake_build_options(self) -> List[Dict[str, str]]:
    """Extract options from CMakeLists.txt file one diretory up. Return as
    list of dictionary items with the name, type and default value of the
    CMake options."""
    option_elements = []

    try:
      output = subprocess.check_output('cmake -LAH ../ || true',
                                       shell=True).decode()
    except subprocess.CalledProcessError:
      return option_elements

    # Parse the CMake options output to extract name, type and default value.
    raw_options = []
    for line in output.split('\n'):
      if ':' in line and '=' in line:
        raw_options.append(line)

    for raw_option in raw_options:
      option_default = raw_option.split('=')[-1]
      option_type = raw_option.split('=')[0].split(':')[1]
      option_name = raw_option.split('=')[0].split(':')[0]

      option_elements.append({
          'name': option_name,
          'type': option_type,
          'default': option_default
      })

    return option_elements

  def extract_options_in_file(self) -> List[Dict[str, str]]:
    """Extract CMake options from the CMakeLists.txt file one directory up."""
    with open('../CMakeLists.txt', 'r') as f:
      cmake_content = f.read()
    cmake_options = self.extract_cmake_build_options()

    # For each option in the cmake entire list of options identify which are
    # defined inside of the CMakeLists.txt file of interest.
    options_in_cmake_file = []
    for option in cmake_options:
      if option['name'] in cmake_content:
        options_in_cmake_file.append(option)
    return options_in_cmake_file

  def extract_defensive_options(self) -> str:
    """Extract options from CMakeLists.txt file as a string where all BOOL
    options are set to False except for those with 'STATIC' in them."""
    options_in_cmake = self.extract_options_in_file()
    cmake_string = ''
    for option in options_in_cmake:
      if option['type'] != 'BOOL':
        continue
      if 'STATIC' in option['name'] and option['default'] != 'ON':
        cmake_string += '-D%s=ON ' % (option['name'])
      elif option['default'] != 'OFF':
        cmake_string += '-D%s=OFF ' % (option['name'])
    return cmake_string


class CMakeScanner(AutoBuildBase):
  """Auto builder for CMake projects."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'CMakeLists.txt': [],
    }

    self.cmake_options = set()

  def match_files(self, file_list: List[str]) -> None:
    for fi in file_list:
      base_file = os.path.basename(fi)
      for key, matches in self.matches_found.items():
        if base_file == key:
          matches.append(fi)

          with open(fi, 'r') as f:
            content = f.read()
          for line in content.split('\n'):
            if 'option(' in line:
              option = line.split('option(')[1].split(' ')[0]
              self.cmake_options.add(option)

    if len(self.cmake_options) > 0:
      logger.info('Options:')
      for option in self.cmake_options:
        logger.info('%s', option)

  def steps_to_build(self):
    # When we are running this, we are confident there are
    # some heuristics that match what is needed for cmake builds.
    # At this point, we will also scan for potential options
    # in the cmake files, such as:
    # - options related to shared libraries.
    # - options related to which packags need installing.
    cmds_to_exec_from_root = [
        'mkdir fuzz-build',
        'cd fuzz-build',
        'cmake -DCMAKE_VERBOSE_MAKEFILE=ON ../',
        'make V=1 || true',
    ]
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + '1'
    yield build_container

    cmake_opts = [
        '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
        '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
    ]

    opt1 = [
        'mkdir fuzz-build',
        'cd fuzz-build',
        'cmake %s ../' % (' '.join(cmake_opts)),
        'make V=1 || true',
    ]
    build_container2 = AutoBuildContainer()
    build_container2.list_of_commands = opt1
    build_container2.heuristic_id = self.name + '2'
    yield build_container2

    # Force static libraryes
    opt_static = [
        'mkdir fuzz-build',
        'cd fuzz-build',
        'cmake %s ../' % (' '.join(cmake_opts)),
        'sed -i \'s/SHARED/STATIC/g\' ../CMakeLists.txt',
        'make V=1 || true',
    ]
    build_container_static = AutoBuildContainer()
    build_container_static.list_of_commands = opt_static
    build_container_static.heuristic_id = self.name + 'static'
    yield build_container_static

    # Look for options often used for disabling dynamic shared libraries.
    option_values = []
    for option in self.cmake_options:
      if 'BUILD_SHARED_LIBS' == option:
        option_values.append('-D%s=OFF' % (option))
      elif 'BUILD_STATIC' == option:
        option_values.append('-D%s=ON' % (option))
      elif 'BUILD_SHARED' == option:
        option_values.append('-D%s=OFF' % (option))
      elif 'ENABLE_STATIC' == option:
        option_values.append('-D%s=ON' % (option))

    if len(option_values) > 0:
      option_string = ' '.join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          'mkdir fuzz-build',
          'cd fuzz-build',
          'cmake %s %s ../' % (' '.join(cmake_default_options), option_string),
          'make V=1',
      ]
      build_container3 = AutoBuildContainer()
      build_container3.list_of_commands = bopt
      build_container3.heuristic_id = self.name + '3'
      yield build_container3

    # Build tests in-case
    # Look for options often used for disabling dynamic shared libraries.
    option_values = []
    for option in self.cmake_options:
      if 'BUILD_SHARED_LIBS' == option:
        option_values.append('-D%s=OFF' % (option))
      elif 'BUILD_STATIC' == option:
        option_values.append('-D%s=ON' % (option))
      elif 'BUILD_SHARED' == option:
        option_values.append('-D%s=OFF' % (option))
      elif 'ENABLE_STATIC' == option:
        option_values.append('-D%s=ON' % (option))
      elif 'BUILD_TESTS' in option:
        option_values.append('-D%s=ON' % (option))

    if len(option_values) > 0:
      option_string = ' '.join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          'mkdir fuzz-build',
          'cd fuzz-build',
          'cmake %s %s ../' % (' '.join(cmake_default_options), option_string),
          'make V=1',
      ]
      build_container4 = AutoBuildContainer()
      build_container4.list_of_commands = bopt
      build_container4.heuristic_id = self.name + '3'
      yield build_container4

  @property
  def name(self):
    return 'cmake'


def match_build_heuristics_on_folder(abspath_of_target: str):
  """Yields AutoBuildContainer objects.

  Traverses the files in the target folder. Uses the file list as input to
  auto build heuristics, and for each heuristic will yield any of the
  build steps that are deemed matching."""
  all_files = manager.get_all_files_in_path(abspath_of_target)
  all_checks = [
      AutogenConfScanner(),
      PureCFileCompiler(),
      PureCFileCompilerFind(),
      PureMakefileScanner(),
      PureMakefileScannerWithPThread(),
      PureMakefileScannerWithSubstitutions(),
      AutogenScanner(),
      AutoRefConfScanner(),
      CMakeScanner(),
      CMakeScannerOptsParser(),
      RawMake(),
      BootstrapScanner(),
      AutogenScannerSH(),
  ]

  checks_to_test = []

  logger.info('Filtering out build scripts')
  build_heuristics_to_analyse = os.getenv('BUILD_HEURISTICS', 'all')
  if build_heuristics_to_analyse == 'all':
    checks_to_test = all_checks
  else:
    all_build_heuristics = build_heuristics_to_analyse.split(',')
    for name in all_build_heuristics:
      for check in all_checks:
        if check.name == name:
          checks_to_test.append(check)

  logger.info('Using %d checks.', len(checks_to_test))
  for scanner in checks_to_test:
    scanner.match_files(all_files)
    if scanner.is_matched():
      logger.info('Matched: %s', scanner.name)
      for auto_build_gen in scanner.steps_to_build():
        yield auto_build_gen


def get_all_binary_files_from_folder(path: str) -> Dict[str, List[str]]:
  """Extracts binary artifacts from a list of files, based on file suffix."""
  all_files = manager.get_all_files_in_path(path, path)

  executable_files = {'static-libs': [], 'dynamic-libs': [], 'object-files': []}
  for fil in all_files:
    if fil.endswith('.o'):
      executable_files['object-files'].append(fil)
    if fil.endswith('.a'):
      executable_files['static-libs'].append(fil)
    if fil.endswith('.so'):
      executable_files['dynamic-libs'].append(fil)
  return executable_files


def wrap_build_script(test_dir: str, build_container: AutoBuildContainer,
                      abspath_of_target: str) -> str:
  build_script = '#!/bin/bash\n'
  build_script += 'rm -rf /%s\n' % (test_dir)
  build_script += 'cp -rf %s %s\n' % (abspath_of_target, test_dir)
  build_script += 'cd %s\n' % (test_dir)
  for cmd in build_container.list_of_commands:
    build_script += cmd + '\n'

  return build_script


def convert_build_heuristics_to_scripts(
    all_build_suggestions: List[AutoBuildContainer], testing_base_dir: str,
    abspath_of_target: str) -> List[Tuple[str, str, AutoBuildContainer]]:
  """Convert Auto build containers into bash scripts."""
  all_build_scripts = []
  for idx, build_suggestion in enumerate(all_build_suggestions):
    test_dir = os.path.abspath(
        os.path.join(os.getcwd(), testing_base_dir + str(idx)))
    build_script = wrap_build_script(test_dir, build_suggestion,
                                     abspath_of_target)
    all_build_scripts.append((build_script, test_dir, build_suggestion))
  return all_build_scripts


def extract_build_suggestions(
    target_dir, testing_base_dir) -> List[Tuple[str, str, AutoBuildContainer]]:
  """Statically create suggested build scripts for a project."""
  # Get all of the build heuristics
  all_build_suggestions: List[AutoBuildContainer] = list(
      match_build_heuristics_on_folder(target_dir))
  logger.info('Found %d possible build suggestions', len(all_build_suggestions))
  #all_build_suggestions = all_build_suggestions[:2]
  for build_suggestion in all_build_suggestions:
    logger.info('- %s', build_suggestion.heuristic_id)

  # Convert the build heuristics into build scripts
  all_build_scripts = convert_build_heuristics_to_scripts(
      all_build_suggestions, testing_base_dir, target_dir)
  return all_build_scripts


def raw_build_evaluation(
    all_build_scripts: List[Tuple[str, str, AutoBuildContainer]],
    initial_executable_files: Dict[str, List[str]]) -> Dict[str, Any]:
  """Run each of the build scripts and extract any artifacts build by them."""
  build_results = {}
  for build_script, test_dir, build_suggestion in all_build_scripts:
    logger.info('Evaluating build heuristic %s', build_suggestion.heuristic_id)
    with open('/src/build.sh', 'w') as bf:
      bf.write(build_script)
    try:
      subprocess.check_call('compile',
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      pass

    # Identify any binary artifacts built that weren't there prior
    # to running the build.
    binary_files_build = get_all_binary_files_from_folder(test_dir)

    new_binary_files = {
        'static-libs': [],
        'dynamic-libs': [],
        'object-files': []
    }
    for key, bfiles in binary_files_build.items():
      for bfile in bfiles:
        if bfile not in initial_executable_files[key]:
          new_binary_files[key].append(bfile)

    logger.info('Static libs found %s', str(new_binary_files))

    # binary_files_build['static-libs'])
    build_results[test_dir] = {
        'build-script': build_script,
        'executables-build': binary_files_build,
        'auto-build-setup': (build_script, test_dir, build_suggestion)
    }
  return build_results
