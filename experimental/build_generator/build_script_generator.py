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
import re
import shutil
import subprocess
from abc import abstractmethod
from typing import Dict, Iterator, List, Optional, Tuple

import constants
import manager
import templates

from llm_toolkit import models

logger = logging.getLogger(name=__name__)


############################################################
#### Logic for auto building a given source code folder ####
############################################################
class AutoBuildContainer:
  """Auto build data container."""

  def __init__(self, old: Optional["AutoBuildContainer"] = None):
    if old:
      self.list_of_commands = old.list_of_commands
      self.list_of_required_packages = old.list_of_required_packages
      self.heuristic_id = old.heuristic_id
    else:
      self.list_of_commands = []
      self.list_of_required_packages = []
      self.heuristic_id = ''


class BuildWorker:
  """Keeper of data on auto generated builds."""

  def __init__(self, build_suggestion: AutoBuildContainer, build_script: str,
               build_directory: str, executable_files_build: Dict[str,
                                                                  List[str]]):
    self.build_suggestion: AutoBuildContainer = build_suggestion
    self.build_script: str = build_script
    self.build_directory: str = build_directory
    self.executable_files_build: Dict[str, List[str]] = executable_files_build
    self.base_fuzz_build: bool = False


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

  def determine_required_packages(
      self, config_file_str: str) -> List[Tuple[str, str]]:
    """Determine additional required package for installation in Dockerfile."""

    # Find all -l<lib> flags in makefile or other configurations
    libs = re.findall(r"-l(\w+)", config_file_str)

    # Map to packages, skipping built-in or unmapped ones
    required_packages = [(f'-l{lib}', constants.LIBRARY_PACKAGE_MAP[lib])
                         for lib in libs
                         if lib in constants.LIBRARY_PACKAGE_MAP]

    return list(set(required_packages))


class LLMBuilder(AutoBuildBase):
  """Using LLM for automatic build script generation."""

  def __init__(self, model_name: str):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
        'configure.ac': [],
        'Makefile.am': [],
        'autogen.sh': [],
        'bootstrap.sh': [],
        'CMakeLists.txt': [],
        'Config.in': [],
    }
    self.model = models.LLM.setup(
        ai_binary=os.getenv('AI_BINARY', ''),
        name=model_name,
        max_tokens=4096,
        num_samples=1,
        temperature=0.4,
        temperature_list=[],
    )
    self.prompt = self.model.prompt_type()(None)

  def is_matched(self):
    """Always true for using LLM support."""
    return True

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    """Yields AutoBuildContainer objects."""
    container = AutoBuildContainer()

    # Retrive a list of known build files from the project.
    build_files = self._retrieve_build_files()
    if build_files:
      self._build_prompt(build_files)
      response = self.model.ask_llm(prompt=self.prompt)
      response = response.replace('```bash', '').replace('```', '')

      container.list_of_commands.append(response)
      container.heuristic_id = self.name + '1'
      logger.info(container.list_of_commands)

    yield container

    # TODO Handle cases for source code only projects.
    directory_tree = self._generate_directory_tree()
    if directory_tree:
      pass

  def _generate_directory_tree(self) -> str:
    """Generate a recusive directory tree string for the target project."""
    return ''

  def _retrieve_build_files(self) -> Dict[str, str]:
    """Retrieve the content of build files mapped to their path."""
    build_files = {}

    for files in self.matches_found.values():
      for file in files:
        with open(file, 'r') as f:
          build_files[file.split('/', 1)[-1]] = f.read()

    return build_files

  def _build_prompt(self, build_files: Dict[str, str]) -> None:
    """Helper to generate prompt for llm model"""
    build_files_str = []
    for file, content in build_files.items():
      target_str = templates.LLM_BUILD_FILE_TEMPLATE.replace('{PATH}', file)
      target_str = target_str.replace('{CONTENT}', content)
      build_files_str.append(target_str)

    problem = templates.LLM_PROBLEM.replace('{BUILD_FILES}',
                                            '\n'.join(build_files_str))

    self.prompt.add_priming(templates.LLM_PRIMING)
    self.prompt.add_problem(problem)

  @property
  def name(self):
    return 'LLM'


class HeaderOnlyCBuilder(AutoBuildBase):
  """Wrapper for building header-only targets"""

  def __init__(self):
    super().__init__()
    self.matches_found = {'.h': []}

  def match_files(self, file_list):
    """Matches files needed for the build heuristic."""
    file_dicts = {
        '.c': [],
        '.h': [],
    }
    for fi in file_list:
      for key, val in file_dicts.items():
        if fi.endswith(key) and 'test' not in fi and 'example' not in fi:
          # Remove the first folder as that is "this" dir.
          path_to_add = '/'.join(fi.split('/')[1:])
          val.append(path_to_add)
    if not file_dicts['.c'] and file_dicts['.h']:
      self.matches_found['.h'] = file_dicts['.h']

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()

    header_writers = ''
    for header_file in self.matches_found['.h']:
      header_writers += f'echo "#include \\"{header_file}\\""'
      header_writers += ' >> empty_wrapper.c\n'

    build_container.list_of_commands = [
        f'''touch empty_wrapper.c
# Write includes for each of the header files
{header_writers}
rm -rf *.o
$CC $CFLAGS -c empty_wrapper.c -o empty_wrapper.o
llvm-ar rcs libfuzz.a *.o
'''
    ]
    build_container.heuristic_id = self.name + '1'
    logger.info(build_container.list_of_commands[0])
    yield build_container

  @property
  def name(self):
    return 'HeaderOnlyCBuilder'


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


class PureCPPFileCompilerFind(AutoBuildBase):
  """Builder for compiling .cpp files direcetly in root repo dir, using find."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        '.cpp': [],
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
        '''find . -name "*.cpp" -exec $CXX $CXXFLAGS -I./src -c {} \\;
find . -name "*.o" -exec cp {} . \\;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o
'''
    ]
    build_container.heuristic_id = self.name + '1'
    yield build_container

  @property
  def name(self):
    return 'PureCPPFileCompilerFind'


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


class PureMakefileScannerWithLibFlag(AutoBuildBase):
  """Auto builder for pure Makefile projects, relying on "make" with
  additional -l flags during linker process."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    # Determine possible lib flags from Makefile
    lib_flags: List[Tuple[str, str]] = []
    for file in self.matches_found['Makefile']:
      with open(file, 'r') as f:
        content = f.read()
        lib_flags.extend(self.determine_required_packages(content))

    # Process required packages
    build_container = AutoBuildContainer()
    flags = []
    for flag, package in lib_flags:
      flags.append(flag)
      if package:
        build_container.list_of_required_packages.append(package)

    # Route 1: Basic build with lib flags
    build_container.list_of_commands = [
        f'make clean && make LDLIBS="{" ".join(flags)}"',
        ('find . -type f -name "*.o" -print0 | '
         'xargs -0 llvm-ar rcs libfuzz.a')
    ]
    build_container.heuristic_id = self.name + '1'
    yield build_container

    # Route 2: Overriding CXXFLAGS
    build_container_2 = AutoBuildContainer(build_container)
    build_container_2.list_of_commands = [
        ('make clean && make CXXFLAGS="$CXXFLAGS"'
         f' LDLIBS="{" ".join(flags)}"'),
        ('find . -type f -name "*.o" -print0 | '
         'xargs -0 llvm-ar rcs libfuzz.a')
    ]
    build_container_2.heuristic_id = self.name + '2'
    yield build_container_2

    # Route 2: Overriding CXXFLAGS and add PIC flag
    build_container_3 = AutoBuildContainer(build_container)
    build_container_3.list_of_commands = [
        ('make clean && make CXXFLAGS="$CXXFLAGS -fPIC"'
         f' LDLIBS="{" ".join(flags)}"'),
        ('find . -type f -name "*.o" -print0 | '
         'xargs -0 llvm-ar rcs libfuzz.a')
    ]
    build_container_3.heuristic_id = self.name + '3'
    yield build_container_3

  @property
  def name(self):
    return 'makewithlibflag'


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
        cmake_string += f'-D{option["name"]}=ON '
      elif option['default'] != 'OFF':
        cmake_string += f'-D{option["name"]}=OFF '
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
        f'cmake {" ".join(cmake_opts)} ../',
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
        f'cmake {" ".join(cmake_opts)} ../',
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
        option_values.append(f'-D{option}=OFF')
      elif 'BUILD_STATIC' == option:
        option_values.append(f'-D{option}=ON')
      elif 'BUILD_SHARED' == option:
        option_values.append(f'-D{option}=OFF')
      elif 'ENABLE_STATIC' == option:
        option_values.append(f'-D{option}=ON')

    if len(option_values) > 0:
      option_string = ' '.join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          'mkdir fuzz-build',
          'cd fuzz-build',
          f'cmake {" ".join(cmake_default_options)} {option_string} ../',
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
        option_values.append(f'-D{option}=OFF')
      elif 'BUILD_STATIC' == option:
        option_values.append(f'-D{option}=ON')
      elif 'BUILD_SHARED' == option:
        option_values.append(f'-D{option}=OFF')
      elif 'ENABLE_STATIC' == option:
        option_values.append(f'-D{option}=ON')
      elif 'BUILD_TESTS' in option:
        option_values.append(f'-D{option}=ON')

    if len(option_values) > 0:
      option_string = ' '.join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          'mkdir fuzz-build',
          'cd fuzz-build',
          f'cmake {" ".join(cmake_default_options)} {option_string} ../',
          'make V=1',
      ]
      build_container4 = AutoBuildContainer()
      build_container4.list_of_commands = bopt
      build_container4.heuristic_id = self.name + '3'
      yield build_container4

  @property
  def name(self):
    return 'cmake'


class KConfigBuildScanner(AutoBuildBase):
  """Auto builder for KConfig-based projects."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Config.in': [],
        'Makefile': [],
    }

  def is_matched(self):
    """Returns True if the build heuristic found matching files."""
    # Ensure both Config.in and Makefile exists
    for found_matches in self.matches_found.values():
      if len(found_matches) == 0:
        return False
    return True

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    base_command = [
        '''
make defconfig
make
find . -type f -name "*.o" > objfiles
llvm-ar rcs libfuzz.a $(cat objfiles)
'''
    ]
    build_container = AutoBuildContainer()
    build_container.list_of_commands = base_command
    build_container.heuristic_id = self.name + '1'
    yield build_container

    # Alternative to avoid Gold lld
    build_container_2 = AutoBuildContainer()
    base_command.append('export CFLAGS="${CFLAGS} -fuse-ld=lld"')
    base_command.append('export CFXXLAGS="${CXXFLAGS} -fuse-ld=lld"')
    build_container_2.list_of_commands = base_command
    build_container.heuristic_id = self.name + '2'
    yield build_container_2

    # Alternative to avoid Gold lld and add thread/crypt libraries
    build_container_3 = AutoBuildContainer()
    base_command.append('export CFLAGS="${CFLAGS} -lpthread -lcrypt"')
    base_command.append('export CFXXLAGS="${CXXFLAGS} -lpthread -lcrypt"')
    build_container_3.list_of_commands = base_command
    build_container.heuristic_id = self.name + '3'
    yield build_container_3

  @property
  def name(self):
    return 'kconfig'


def match_build_heuristics_on_folder(abspath_of_target: str, model_name: str):
  """Yields AutoBuildContainer objects.

  Traverses the files in the target folder. Uses the file list as input to
  auto build heuristics, and for each heuristic will yield any of the
  build steps that are deemed matching."""
  all_files = manager.get_all_files_in_path(abspath_of_target)
  all_checks = [
      LLMBuilder(model_name),
      AutogenConfScanner(),
      PureCFileCompiler(),
      PureCFileCompilerFind(),
      PureCPPFileCompilerFind(),
      PureMakefileScanner(),
      PureMakefileScannerWithPThread(),
      PureMakefileScannerWithSubstitutions(),
      PureMakefileScannerWithLibFlag(),
      AutogenScanner(),
      AutoRefConfScanner(),
      CMakeScanner(),
      CMakeScannerOptsParser(),
      RawMake(),
      BootstrapScanner(),
      AutogenScannerSH(),
      HeaderOnlyCBuilder(),
      KConfigBuildScanner(),
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
      yield from scanner.steps_to_build()


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
  build_script += f'rm -rf /{test_dir}\n'
  build_script += f'cp -rf {abspath_of_target} {test_dir}\n'
  build_script += f'cd {test_dir}\n'
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
    target_dir, testing_base_dir,
    model_name) -> List[Tuple[str, str, AutoBuildContainer]]:
  """Statically create suggested build scripts for a project."""
  # Get all of the build heuristics
  all_build_suggestions: List[AutoBuildContainer] = list(
      match_build_heuristics_on_folder(target_dir, model_name))
  logger.info('Found %d possible build suggestions', len(all_build_suggestions))
  #all_build_suggestions = all_build_suggestions[:2]
  for build_suggestion in all_build_suggestions:
    logger.info('- %s', build_suggestion.heuristic_id)

  # Convert the build heuristics into build scripts
  all_build_scripts = convert_build_heuristics_to_scripts(
      all_build_suggestions, testing_base_dir, target_dir)
  return all_build_scripts


def raw_build_evaluation(
    all_build_scripts: List[Tuple[str, str, AutoBuildContainer]]
) -> Dict[str, BuildWorker]:
  """Run each of the build scripts and extract any artifacts build by them."""
  build_results = {}
  for build_script, test_dir, build_suggestion in all_build_scripts:
    logger.info('Evaluating build heuristic %s', build_suggestion.heuristic_id)
    with open('/src/build.sh', 'w') as bf:
      bf.write(build_script)

    pkgs = build_suggestion.list_of_required_packages
    if pkgs:
      command = f'apt install -y {" ".join(pkgs)} && compile'
    else:
      command = 'compile'
    try:
      subprocess.check_call(command,
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
      pass
    logger.info('Finished evaluation.')
    # Identify any binary artifacts built that weren't there prior
    # to running the build.
    logger.info('Finding executables')
    binary_files_build = get_all_binary_files_from_folder(test_dir)
    logger.info('Finished looking for executables.')

    build_worker = BuildWorker(build_suggestion, build_script, test_dir,
                               binary_files_build)

    build_results[test_dir] = build_worker

  return build_results
