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
import os
import shutil
import subprocess
from abc import abstractmethod
from typing import Any, Dict, Iterator, List, Optional, Tuple

import cxxfilt
import openai
import yaml

MAX_FUZZ_PER_HEURISTIC = 15
INTROSPECTOR_OSS_FUZZ_DIR = '/src/inspector'

client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

FUZZER_PRE_HEADERS = """#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
"""

CPP_BASE_TEMPLATE = """#include <stdint.h>
#include <iostream>

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    // Insert fuzzer contents here
    // input string contains fuzz input.

    // end of fuzzer contents

    return 0;
}"""


############################################################
#### Logic for auto building a given source code folder ####
############################################################
class AutoBuildContainer:

  def __init__(self):
    self.list_of_commands = []
    self.heuristic_id = ""


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
    for matches in self.matches_found:
      if len(matches) == 0:
        return False
    return True


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
        if fi.endswith(key) and "test" not in fi and "example" not in fi:
          print("Adding %s" % (fi))
          # Remove the first folder as that is "this" dir.
          path_to_add = '/'.join(fi.split('/')[1:])
          val.append(path_to_add)

  def steps_to_build(self) -> Iterator[AutoBuildContainer]:
    build_container = AutoBuildContainer()
    build_container.list_of_commands = [
        """for file in "%s"; do
  $CC $CFLAGS -c ${file}
done

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o
""" % (" ".join(self.matches_found['.c']))
    ]
    build_container.heuristic_id = self.name + "1"
    print(build_container.list_of_commands[0])
    yield build_container

  @property
  def name(self):
    return "pureCFileCompiler"


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
        """find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \\;
find . -name "*.o" -exec cp {} . \\;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o
"""
    ]
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "pureCFileCompilerFind"


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
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "make"


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
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "make"


class AutoRefConfScanner(AutoBuildBase):
  """Auto-builder for patterns of "autoreconf fi; ./configure' make"""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile.am': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ["autoreconf -fi", "./configure", "make"]
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "autogen"


class RawMake(AutoBuildBase):
  """Similar to PureMake but also adds option for "make test". This is useful
  to trigger more Fuzz Introspector analysis in the project."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ["make"]
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + "1"
    yield build_container

    build_container2 = AutoBuildContainer()
    build_container2.list_of_commands = cmds_to_exec_from_root + ["make test"]
    build_container2.heuristic_id = self.name + "1"
    yield build_container2

  @property
  def name(self):
    return "RawMake"


class AutogenScanner(AutoBuildBase):
  """Auto builder for projects relying on "autoconf; autoheader."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ["autoconf", "autoheader", "./configure", "make"]
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "autogen"


class AutogenConfScanner(AutoBuildBase):
  """Auto builder for projects relying on "autoconf; autoheader."""

  def __init__(self):
    super().__init__()
    self.matches_found = {
        'configure.ac': [],
        'Makefile': [],
    }

  def steps_to_build(self):
    cmds_to_exec_from_root = ["./configure", "make"]
    #yield cmds_to_exec_from_root
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + "1"
    yield build_container

  @property
  def name(self):
    return "autogen-ConfMake"


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

          with open(fi, "r") as f:
            content = f.read()
          for line in content.split("\n"):
            if "option(" in line:
              option = line.split("option(")[1].split(" ")[0]
              self.cmake_options.add(option)

    if len(self.cmake_options) > 0:
      print("Options:")
      for option in self.cmake_options:
        print("%s" % (option))

  def steps_to_build(self):
    # When we are running this, we are confident there are
    # some heuristics that match what is needed for cmake builds.
    # At this point, we will also scan for potential options
    # in the cmake files, such as:
    # - options related to shared libraries.
    # - options related to which packags need installing.
    cmds_to_exec_from_root = [
        "mkdir fuzz-build",
        "cd fuzz-build",
        "cmake -DCMAKE_VERBOSE_MAKEFILE=ON ../",
        "make V=1 || true",
    ]
    build_container = AutoBuildContainer()
    build_container.list_of_commands = cmds_to_exec_from_root
    build_container.heuristic_id = self.name + "1"
    yield build_container

    cmake_opts = [
        '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
        '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
    ]

    opt1 = [
        "mkdir fuzz-build",
        "cd fuzz-build",
        "cmake %s ../" % (' '.join(cmake_opts)),
        "make V=1 || true",
    ]
    build_container2 = AutoBuildContainer()
    build_container2.list_of_commands = opt1
    build_container2.heuristic_id = self.name + "2"
    yield build_container2

    # Force static libraryes
    opt_static = [
        "mkdir fuzz-build",
        "cd fuzz-build",
        "cmake %s ../" % (' '.join(cmake_opts)),
        'sed -i \'s/SHARED/STATIC/g\' ../CMakeLists.txt',
        "make V=1 || true",
    ]
    build_container_static = AutoBuildContainer()
    build_container_static.list_of_commands = opt_static
    build_container_static.heuristic_id = self.name + "static"
    yield build_container_static

    # Look for options often used for disabling dynamic shared libraries.
    option_values = []
    for option in self.cmake_options:
      if "BUILD_SHARED_LIBS" == option:
        option_values.append("-D%s=OFF" % (option))
      elif "BUILD_STATIC" == option:
        option_values.append("-D%s=ON" % (option))
      elif "BUILD_SHARED" == option:
        option_values.append("-D%s=OFF" % (option))
      elif "ENABLE_STATIC" == option:
        option_values.append("-D%s=ON" % (option))

    if len(option_values) > 0:
      option_string = " ".join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          "mkdir fuzz-build",
          "cd fuzz-build",
          "cmake %s %s ../" % (' '.join(cmake_default_options), option_string),
          "make V=1",
      ]
      build_container3 = AutoBuildContainer()
      build_container3.list_of_commands = bopt
      build_container3.heuristic_id = self.name + "3"
      yield build_container3

    # Build tests in-case
    # Look for options often used for disabling dynamic shared libraries.
    option_values = []
    for option in self.cmake_options:
      if "BUILD_SHARED_LIBS" == option:
        option_values.append("-D%s=OFF" % (option))
      elif "BUILD_STATIC" == option:
        option_values.append("-D%s=ON" % (option))
      elif "BUILD_SHARED" == option:
        option_values.append("-D%s=OFF" % (option))
      elif "ENABLE_STATIC" == option:
        option_values.append("-D%s=ON" % (option))
      elif "BUILD_TESTS" in option:
        option_values.append("-D%s=ON" % (option))

    if len(option_values) > 0:
      option_string = " ".join(option_values)
      cmake_default_options = [
          '-DCMAKE_VERBOSE_MAKEFILE=ON', '-DCMAKE_CXX_COMPILER=$CXX',
          '-DCMAKE_CXX_FLAGS=\"$CXXFLAGS\"'
      ]
      bopt = [
          "mkdir fuzz-build",
          "cd fuzz-build",
          "cmake %s %s ../" % (' '.join(cmake_default_options), option_string),
          "make V=1",
      ]
      build_container4 = AutoBuildContainer()
      build_container4.list_of_commands = bopt
      build_container4.heuristic_id = self.name + "3"
      yield build_container4

  @property
  def name(self):
    return "cmake"


def get_all_files_in_path(base_path: str,
                          path_to_subtract: Optional[str] = None) -> List[str]:
  """Gets all files in a tree and returns as a list of strings."""
  all_files = []
  if path_to_subtract is None:
    path_to_subtract = os.getcwd()
  for root, _, files in os.walk(base_path):
    for fi in files:
      path = os.path.join(root, fi)
      if path.startswith(path_to_subtract):
        path = path[len(path_to_subtract):]
      if len(path) > 0 and path[0] == '/':
        path = path[1:]
      all_files.append(path)
  return all_files


def get_all_binary_files_from_folder(path: str) -> Dict[str, List[str]]:
  """Extracts binary artifacts from a list of files, based on file suffix."""
  all_files = get_all_files_in_path(path, path)

  executable_files = {'static-libs': [], 'dynamic-libs': [], 'object-files': []}
  for fil in all_files:
    if fil.endswith(".o"):
      executable_files['object-files'].append(fil)
    if fil.endswith(".a"):
      executable_files['static-libs'].append(fil)
    if fil.endswith(".so"):
      executable_files['dynamic-libs'].append(fil)
  return executable_files


def match_build_heuristics_on_folder(abspath_of_target: str):
  """Yields AutoBuildContainer objects.

  Traverses the files in the target folder. Uses the file list as input to
  auto build heuristics, and for each heuristic will yield any of the
  build steps that are deemed matching."""
  all_files = get_all_files_in_path(abspath_of_target)
  all_checks = [
      AutogenConfScanner(),
      PureCFileCompiler(),
      PureCFileCompilerFind(),
      PureMakefileScanner(),
      PureMakefileScannerWithPThread(),
      AutogenScanner(),
      AutoRefConfScanner(),
      CMakeScanner(),
      RawMake(),
  ]

  for scanner in all_checks:
    scanner.match_files(all_files)
    if scanner.is_matched():
      print("Matched: %s" % (scanner.name))
      for auto_build_gen in scanner.steps_to_build():
        # print("Build script: ")
        yield auto_build_gen


def wrap_build_script(test_dir: str, build_container: AutoBuildContainer,
                      abspath_of_target: str) -> str:
  build_script = "#!/bin/bash\n"
  build_script += "rm -rf /%s\n" % (test_dir)
  build_script += "cp -rf %s %s\n" % (abspath_of_target, test_dir)
  build_script += "cd %s\n" % (test_dir)
  for cmd in build_container.list_of_commands:
    build_script += cmd + "\n"

  return build_script


def get_all_functions_in_project(introspection_files_found):
  all_functions_in_project = []
  for fi_yaml_file in introspection_files_found:
    with open(fi_yaml_file, "r") as file:
      yaml_content = yaml.safe_load(file)
    for elem in yaml_content['All functions']['Elements']:
      all_functions_in_project.append(elem)

  return all_functions_in_project


##################################################
#### Heuristics for auto generating harnesses ####
##################################################

GLOBAL_FUZZER_SOURCE_CACHE = {}


def get_source_from_cache(heuristic_name, target_func):
  funcs_in_cache = GLOBAL_FUZZER_SOURCE_CACHE.get(heuristic_name, [])
  if len(funcs_in_cache) == 0:
    return None
  for func, target_source in funcs_in_cache:
    if func['Func name'] == target_func['Func name']:
      return target_source
  return None


def add_to_source_cache(heuristic_name, target_func, fuzzer_source):
  funcs_in_cache = GLOBAL_FUZZER_SOURCE_CACHE.get(heuristic_name, [])
  funcs_in_cache.append((target_func, fuzzer_source))
  GLOBAL_FUZZER_SOURCE_CACHE[heuristic_name] = funcs_in_cache


class FuzzHeuristicGeneratorBase:
  """Base class for fuzzer heuristics generator."""

  def __init__(self, test_dir):
    self.test_dir = test_dir
    self.all_header_files = []
    self.all_functions_in_project = []
    self.introspector_report = {}

  @abstractmethod
  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    """generates fuzzer source code, build and include directives."""

  @abstractmethod
  def get_fuzzing_targets(self) -> List[Any]:
    """Gets a list of possible function targets."""

  def get_header_intrinsics(self):
    """All header files and include directories."""
    headers_to_include = set()
    header_paths_to_include = set()
    for header_file in self.all_header_files:
      #print("- %s"%(header_file))
      if "/test/" in header_file:
        continue
      if "googletest" in header_file:
        continue
      headers_to_include.add(os.path.basename(header_file))
      header_paths_to_include.add("/".join(header_file.split("/")[1:-1]))

    # Generate -I strings to be used in the build command.
    build_command_includes = ""
    for header_path_to_include in header_paths_to_include:
      build_command_includes += "-I" + os.path.join(
          self.test_dir, header_path_to_include) + " "

    return headers_to_include, header_paths_to_include, build_command_includes

  def run_prompt_and_get_fuzzer_source(self, prompt):
    """Communicate to OpenAI prompt and extract harness source code."""
    completion = client.chat.completions.create(model="gpt-3.5-turbo",
                                                messages=[
                                                    {
                                                        "role": "system",
                                                        "content": prompt
                                                    },
                                                ])
    fuzzer_source = completion.choices[0].message.content
    if fuzzer_source is None:
      return ""
    fuzzer_source = fuzzer_source.replace("<code>",
                                          "").replace("</code>",
                                                      "").replace("```", "")
    print(">" * 45 + " Source:")
    print(fuzzer_source)
    print("-" * 65)
    return fuzzer_source

  def get_all_functions_sorted_by_cyclomatic_complexity(self) -> List[Any]:
    """Get functions from Fuzz Introspector sorted by cyclomatic complexity."""

    all_funcs = sorted(
        self.introspector_report['MergedProjectProfile']['all-functions'],
        key=lambda x: x['Accumulated cyclomatic complexity'],
        reverse=True)

    #for tdi in range(min(20, len(first_refined_functions_in_project))):
    uniqes = set()
    #idx = 0
    uniq_targets = []
    for func in all_funcs:
      if func['Func name'] in uniqes:
        continue
      if func['Func name'] == 'main':
        continue
      uniqes.add(func['Func name'])
      uniq_targets.append(func)
      print("Target: %s" % (func['Func name']))
      print(" - Cyclomatic: %d" % (func['Accumulated cyclomatic complexity']))

    return uniq_targets


class FuzzerGenHeuristic4(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.name = 'FuzzerGenHeuristic4'
    self.github_url = ""

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    (headers_to_include, _,
     build_command_includes) = self.get_header_intrinsics()

    type_constraints = "the types of types function are:\n"
    for idx, arg in enumerate(func['debug_function_info']['args']):
      type_constraints += "- Argument %d is of type \"%s\"\n" % (idx + 1, arg)
    type_constraints += ("You must make sure the arguments passed to the " +
                         "function matches the types of the function")

    print("Sample targets:")
    prompt = """Hi, please write a fuzz harness for me.

The target project is %s which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function %s.`

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is %s. Make sure to not include any header files not in this list.

Finally, %s

The most important part of the harness is that it will build and compile correctly against the target code. Please focus on making the code as simple as possible in order to secure it can be build.
""" % (self.github_url, func['Func name'], str(headers_to_include),
       type_constraints)

    print("-" * 45)
    print(prompt)
    print("-" * 45)

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      comment_on_target = f'// Target: {func["Func name"]}\n'
      fuzzer_source = comment_on_target + FUZZER_PRE_HEADERS + fuzzer_source

      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      print(f"Using cached fuzzer source\n{fuzzer_source}")

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': '%s-%s' % (self.name, fuzzer_target_call),
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic1(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.name = 'FuzzerGenHeuristic1'
    self.github_url = ""

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()

    print("Sample targets:")
    prompt = """Hi, please write a fuzz harness for me.

The target project is %s which is a open source project written in C. The harness you write should be in pure C as well.

I would like for you to write the harness targeting the function %s.`

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There is one rule that your harness must satisfy: all of the header files in this library is %s. Make sure to not include any header files not in this list.
""" % (self.github_url, func['Func name'], str(headers_to_include))

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      fuzzer_source = FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      print(f"Using cached fuzzer source\n{fuzzer_source}")

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': '%s-%s' % (self.name, fuzzer_target_call),
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic2(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.name = 'FuzzerGenHeuristic2'
    self.github_url = ""

  def get_fuzzing_targets(self) -> List[Any]:
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()

    print("Sample targets:")
    prompt = """Hi, please write a fuzz harness for me.

The target project is %s which is a open source project written in CPP.

I would like for you to write the harness targeting the function %s.

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There are two rules that your harness must satisfy: First, all of the header files in this library is %s. Make sure to not include any header files not in this list. Second, you must wrap the harness such that it catches all exceptions (use "...") thrown by the target code.
""" % (self.github_url, func['Func name'], str(headers_to_include))

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      fuzzer_source = FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      print(f"Using cached fuzzer source\n{fuzzer_source}")

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': '%s-%s' % (self.name, fuzzer_target_call),
    }

    return fuzzer_intrinsics


class FuzzerGenHeuristic3(FuzzHeuristicGeneratorBase):
  """Simple LLM fuzz heuristic."""

  def __init__(self, introspector_report, all_header_files, test_dir):
    super().__init__(test_dir)
    self.introspector_report = introspector_report
    self.all_header_files = all_header_files
    self.name = 'FuzzerGenHeuristic3'
    self.github_url = ""

  def get_fuzzing_targets(self) -> List[Any]:
    """Target selector."""
    return self.get_all_functions_sorted_by_cyclomatic_complexity(
    )[:MAX_FUZZ_PER_HEURISTIC]

  def get_fuzzer_intrinsics(self, func) -> Dict[str, Any]:
    """Harness generator."""
    headers_to_include, _, build_command_includes = self.get_header_intrinsics()

    prompt = """Hi, please write a fuzz harness for me.

The target project is %s which is a open source project written in CPP.

I would like for you to write the harness targeting the function %s.

The harness should be in libFuzzer style, with the code wrapped in LLVMFuzzerTestOneInput.

Please wrap all code in <code> tags and you should include nothing else but the code in your reply. Do not include any other text.

Make sure the ensure strings passed to the target are null-terminated.

There are two rules that your harness must satisfy: First, all of the header files in this library is %s. Make sure to not include any header files not in this list and only include the ones relevant for the target function. Second, if the target is CPP then you must wrap the harness such that it catches all exceptions (use "...") thrown by the target code.
""" % (self.github_url, func['Func name'], str(headers_to_include))

    fuzzer_source = get_source_from_cache(self.name, func)
    if not fuzzer_source:
      fuzzer_source = self.run_prompt_and_get_fuzzer_source(prompt)
      fuzzer_source = FUZZER_PRE_HEADERS + fuzzer_source
      add_to_source_cache(self.name, func, fuzzer_source)
    else:
      print(f"Using cached fuzzer source\n{fuzzer_source}")

    fuzzer_target_call = func['Func name']
    fuzzer_intrinsics = {
        'full-source-code': fuzzer_source,
        'build-command-includes': build_command_includes,
        'autogen-id': '%s-%s' % (self.name, fuzzer_target_call),
    }

    return fuzzer_intrinsics


def refine_and_filter_introspector_functions(all_functions_in_project):
  """Converts raw list of fuzz introspector functions to a refined list."""
  first_refined_functions_in_project = []
  for func in all_functions_in_project:
    to_cont = True
    try:
      demangled = cxxfilt.demangle(func['functionName'])
    except:
      demangled = func['functionName']

    discarded_function_names = {'cxx_global_var_init'}
    for funcname in discarded_function_names:
      if funcname in demangled:
        to_cont = False
        break

    src_file = func['functionSourceFile']
    if src_file.strip() == "":
      continue
    discarded_paths = {
        "googletest",
        "usr/local/bin",
    }

    for discarded_path in discarded_paths:
      if discarded_path in src_file:
        to_cont = False
        break

    # Exit if we need to.
    if not to_cont:
      continue

    func['Func name'] = demangled
    first_refined_functions_in_project.append(func)
  return first_refined_functions_in_project


def get_all_header_files(all_files: List[str]) -> List[str]:
  all_header_files = []
  for yaml_file in all_files:
    if yaml_file.endswith(".h"):
      all_header_files.append(yaml_file)
  return all_header_files


def get_all_introspector_files(target_dir):
  all_files = get_all_files_in_path(target_dir)
  introspection_files_found = []
  for yaml_file in all_files:
    if "allFunctionsWithMain" in yaml_file:
      #print(yaml_file)
      introspection_files_found.append(yaml_file)
    elif 'fuzzerLogFile-' in yaml_file and yaml_file.endswith('.yaml'):
      introspection_files_found.append(yaml_file)
  return introspection_files_found


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
  print("Found %d possible build suggestions" % (len(all_build_suggestions)))
  #all_build_suggestions = all_build_suggestions[:2]
  for build_suggestion in all_build_suggestions:
    print(f'- {build_suggestion.heuristic_id}')

  # Convert the build heuristics into build scripts
  all_build_scripts = convert_build_heuristics_to_scripts(
      all_build_suggestions, testing_base_dir, target_dir)
  return all_build_scripts


def build_empty_fuzzers(results):
  """Run build scripts against an empty fuzzer harness."""
  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.

  # For each of the auto generated build scripts try to link
  # the resulting static libraries against an empty fuzzer.
  for test_dir in results:
    print("Test dir: %s :: %s" %
          (test_dir, str(results[test_dir]['refined-static-libs'])))

    if len(results[test_dir]['refined-static-libs']) == 0:
      continue

    print("Trying to link in an empty fuzzer")

    empty_fuzzer_file = '/src/empty-fuzzer.cpp'
    with open(empty_fuzzer_file, "w") as f:
      f.write(CPP_BASE_TEMPLATE)

    # Try to link the fuzzer to the static libs
    cmd = [
        "clang++", "-fsanitize=fuzzer", "-fsanitize=address", empty_fuzzer_file
    ]
    for refined_static_lib in results[test_dir]['refined-static-libs']:
      cmd.append(os.path.join(test_dir, refined_static_lib))

    print("Command [%s]" % (" ".join(cmd)))

    try:
      subprocess.check_call(" ".join(cmd), shell=True)
      base_fuzz_build = True
    except subprocess.CalledProcessError:
      base_fuzz_build = False

    print("Base fuzz build: %s" % (str(base_fuzz_build)))
    results[test_dir]['base-fuzz-build'] = base_fuzz_build


def refine_static_libs(results):
  """Create a new list for each build the contains the static libraries
  build with the substitution of common gtest libraries, which should not be
  linked in the fuzzer builds."""
  for test_dir in results:
    refined_static_list = []
    libs_to_avoid = {
        "libgtest.a", "libgmock.a", "libgmock_main.a", "libgtest_main.a"
    }
    for static_lib in results[test_dir]['executables-build']['static-libs']:
      if any(
          os.path.basename(static_lib) in lib_to_avoid
          for lib_to_avoid in libs_to_avoid):
        continue
      refined_static_list.append(static_lib)

    results[test_dir]['refined-static-libs'] = refined_static_list


def raw_build_evaluation(
    all_build_scripts: List[Tuple[str, str, AutoBuildContainer]],
    initial_executable_files: Dict[str, List[str]]) -> Dict[str, Any]:
  """Run each of the build scripts and extract any artifacts build by them."""
  build_results = {}
  for build_script, test_dir, build_suggestion in all_build_scripts:
    print(f'Evaluating build heuristic {build_suggestion.heuristic_id}')
    with open("/src/build.sh", "w") as bf:
      bf.write(build_script)
    try:
      subprocess.check_call("compile",
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

    print(f'Static libs found {new_binary_files}')
    # binary_files_build['static-libs'])
    build_results[test_dir] = {
        'build-script': build_script,
        'executables-build': binary_files_build,
        'auto-build-setup': (build_script, test_dir, build_suggestion)
    }
  return build_results


def run_introspector_on_dir(build_results, test_dir) -> Tuple[bool, List[str]]:
  """Runs Fuzz Introspector on a target directory with the ability
    to analyse code without having fuzzers (FUZZ_INTROSPECTOR_AUTO_FUZZ=1).

    This is done by running the bbuild script that succeeded using introspector
    sanitizer from OSS-Fuzz, where introspector will collect data form any
    executable linked during the vanilla build.

    This is done by way of the OSS-Fuzz `compile` command and by setting
    the environment appropriately before running this command.
    """
  introspector_vanilla_build_script = build_results[test_dir]['build-script']

  empty_fuzzer_file = '/src/empty-fuzzer.cpp'
  with open(empty_fuzzer_file, "w") as f:
    f.write(CPP_BASE_TEMPLATE)

  # Try to link the fuzzer to the static libs
  fuzzer_build_cmd = [
      "$CXX", "$CXXFLAGS", "$LIB_FUZZING_ENGINE", empty_fuzzer_file
  ]
  for refined_static_lib in build_results[test_dir]['refined-static-libs']:
    fuzzer_build_cmd.append('-Wl,--whole-archive')
    fuzzer_build_cmd.append(os.path.join(test_dir, refined_static_lib))

  fuzzer_build_cmd.append('-Wl,--allow-multiple-definition')
  introspector_vanilla_build_script += "\n%s" % (" ".join(fuzzer_build_cmd))

  with open("/src/build.sh", "w") as bs:
    bs.write(introspector_vanilla_build_script)

  modified_env = os.environ
  modified_env['SANITIZER'] = 'introspector'
  modified_env['FUZZ_INTROSPECTOR_AUTO_FUZZ'] = "1"
  modified_env['PROJECT_NAME'] = 'auto-fuzz-proj'
  modified_env['FUZZINTRO_OUTDIR'] = test_dir
  try:
    subprocess.check_call("compile",
                          shell=True,
                          env=modified_env,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    build_returned_error = False
  except subprocess.CalledProcessError:
    build_returned_error = True
  print("Introspector build: %s" % (str(build_returned_error)))
  return build_returned_error, fuzzer_build_cmd


def log_fuzzer_source(full_fuzzer_source: str):
  print(">>>>")
  print(full_fuzzer_source)
  print("<<<<")


def generate_harness_intrinsics(
    heuristic: FuzzHeuristicGeneratorBase,
    results,
    test_dir: str,
    fuzzer_build_cmd: List[str],
    verbose_logging: bool = True) -> List[Dict[str, Any]]:
  """Get fuzzer source code, build script and misc for each heuristic."""

  # Get list of target functions for the heuristic.
  fuzzer_targets = heuristic.get_fuzzing_targets()
  print("Found %d fuzzer targets" % (len(fuzzer_targets)))

  # For each target function do:
  # 1) Use the heuristic to generate intrinsics:
  #    - Fuzzer source code
  #    - Include folders for the build script
  # 2) Create the build command needed for the fuzzer, by extending
  #    `fuzzer_build_cmd`
  # 3) Wrap the above in a dictionary and append to results list.
  harness_builds_to_validate = []
  for fuzz_target in fuzzer_targets:
    # Get intrinsics for the target function.
    fuzzer_intrinsics = heuristic.get_fuzzer_intrinsics(fuzz_target)
    if fuzzer_intrinsics is None:
      continue

    if verbose_logging:
      print('[+] Fuzzer generated:')
      print(f'- Fuzz generator id: {fuzzer_intrinsics["autogen-id"]}')
      print(
          f'- Build cmd includes {fuzzer_intrinsics["build-command-includes"]}')
      print('- Source code:')
      log_fuzzer_source(fuzzer_intrinsics['full-source-code'])

    # Generate a build script for compiling the fuzzer with ASAN.
    final_asan_build_script = results[test_dir]['build-script']
    fuzzer_out = '/src/generated-fuzzer'
    final_asan_build_script += "\n%s %s -o %s" % (
        " ".join(fuzzer_build_cmd), fuzzer_intrinsics['build-command-includes'],
        fuzzer_out)

    # Wrap all parts we need for building and running the fuzzer.
    harness_builds_to_validate.append({
        'build-script': final_asan_build_script,
        'source': fuzzer_intrinsics['full-source-code'],
        'fuzzer-file': '/src/empty-fuzzer.cpp',
        'fuzzer-out': fuzzer_out,
        'fuzzer-intrinsics': fuzzer_intrinsics,
    })
  return harness_builds_to_validate


def evaluate_heuristic(test_dir, result_to_validate, fuzzer_intrinsics,
                       heuristics_passed, idx_to_use,
                       disable_fuzz_build_and_test, folders_with_results,
                       outdir):
  """For a given result, will write the harness and build to the file system
  and run the OSS-Fuzz `compile` command to verify that the build script +
  harness builds."""

  print("Fuzzer gen dir:")
  print(os.path.basename(test_dir) + "-fuzzgen-%d" % (idx_to_use))

  fuzzer_gen_dir = os.path.join(
      '/src',
      os.path.basename(test_dir) + "-fuzzgen-%d" % (idx_to_use))
  print("- %s" % (fuzzer_gen_dir))
  if os.path.isdir(fuzzer_gen_dir):
    shutil.rmtree(fuzzer_gen_dir)
  os.mkdir(fuzzer_gen_dir)

  # Write the fuzzer in the directory where we store the source code, just
  # for covenience so we can easily see later.
  with open(os.path.join(fuzzer_gen_dir, 'build.sh'), 'w') as f:
    f.write(result_to_validate['build-script'])
  with open(os.path.join(fuzzer_gen_dir, 'empty-fuzzer.cpp'), 'w') as f:
    f.write(result_to_validate['source'])

  # Write the build/fuzzer files as used by oss-fuzz and the build script.
  with open(result_to_validate['fuzzer-file'], 'w') as f:
    f.write(result_to_validate['source'])
  with open('/src/build.sh', 'w') as f:
    f.write(result_to_validate['build-script'])

  # Skip build process if specified.
  if disable_fuzz_build_and_test:
    return

  # Cleanup any existing fuzzers
  if os.path.isfile(result_to_validate['fuzzer-out']):
    os.remove(result_to_validate['fuzzer-out'])

  modified_env = os.environ
  modified_env['SANITIZER'] = 'address'
  build_out = open(os.path.join(fuzzer_gen_dir, 'fuzz-build.out'), 'w')
  build_err = open(os.path.join(fuzzer_gen_dir, 'fuzz-build.err'), 'w')
  try:
    subprocess.check_call("compile",
                          shell=True,
                          env=modified_env,
                          stdout=build_out,
                          stderr=build_err)
    print("[+] Harness build succeeded")
    build_returned_error = False
  except subprocess.CalledProcessError:
    print("[+] Harness build failed")
    build_returned_error = True

  destination_folder = os.path.join(
      fuzzer_gen_dir,
      os.path.basename(test_dir) + '-fuzzer-generated-%d' % (idx_to_use))

  folders_with_results.add(fuzzer_gen_dir)
  if os.path.isfile(result_to_validate['fuzzer-out']):
    shutil.copy(result_to_validate['fuzzer-out'], destination_folder)

  # Copy artifacts to fuzzer_gen_dir if build was successful.
  if build_returned_error is False:
    heuristics_passed[fuzzer_intrinsics['autogen-id']] = True

  # Run the fuzzer and observer error
  if not os.path.isfile(
      '/src/generated-fuzzer'):  #result_to_validate['fuzzer-out']):
    print("No fuzzing harness executable")
    print("Copying [%s] to [%s]" %
          (fuzzer_gen_dir, os.path.join(outdir,
                                        os.path.basename(fuzzer_gen_dir))))
    shutil.copytree(fuzzer_gen_dir,
                    os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))
    return

  print("Running fuzzer")
  run_out = open(os.path.join(fuzzer_gen_dir, 'fuzz-run.out'), 'w')
  run_err = open(os.path.join(fuzzer_gen_dir, 'fuzz-run.err'), 'w')
  try:
    subprocess.check_call("%s -max_total_time=10" %
                          (result_to_validate['fuzzer-out']),
                          shell=True,
                          env=modified_env,
                          stdout=run_out,
                          stderr=run_err)
    build_returned_error = False
    print("[+] Harness build succeeded")
  except subprocess.CalledProcessError:
    print("[+] Harness build failed")
    build_returned_error = True

  print(
      "Copying 2 [%s] to [%s]" %
      (fuzzer_gen_dir, os.path.join(outdir, os.path.basename(fuzzer_gen_dir))))
  shutil.copytree(fuzzer_gen_dir,
                  os.path.join(outdir, os.path.basename(fuzzer_gen_dir)))


def append_to_report(outdir, msg):
  if not os.path.isdir(outdir):
    os.mkdir(outdir)
  report_path = os.path.join(outdir, 'report.txt')
  with open(report_path, 'a+') as f:
    f.write(msg + '\n')


def load_introspector_report():
  if not os.path.isfile(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR,
                                     'summary.json')):
    return None
  with open(os.path.join(INTROSPECTOR_OSS_FUZZ_DIR, 'summary.json'), 'r') as f:
    return json.loads(f.read())


def auto_generate(github_url,
                  disable_testing_build_scripts=False,
                  disable_fuzzgen=False,
                  disable_fuzz_build_and_test=False,
                  outdir=""):
  """Generates build script and fuzzer harnesses for a GitHub repository."""
  dst_folder = github_url.split("/")[-1]

  # clone the base project into a dedicated folder
  if not os.path.isdir(dst_folder):
    subprocess.check_call("git clone --recurse-submodules %s %s" %
                          (github_url, dst_folder),
                          shell=True)

  # Stage 1: Build script generation
  initial_executable_files = get_all_binary_files_from_folder(
      os.path.abspath(os.path.join(os.getcwd(), dst_folder)))

  # record the path
  abspath_of_target = os.path.join(os.getcwd(), dst_folder)
  print("[+] Extracting build scripts statically")
  all_build_scripts: List[Tuple[
      str, str,
      AutoBuildContainer]] = extract_build_suggestions(abspath_of_target,
                                                       "test-fuzz-build-")

  # return now if we don't need to test build scripts
  if disable_testing_build_scripts is True:
    return

  # Check each of the build scripts.
  print('[+] Testing build suggestions')
  build_results = raw_build_evaluation(all_build_scripts,
                                       initial_executable_files)
  print(f'Checking results of {len(build_results)} build generators')
  for test_dir, test_build_result in build_results.items():
    build_heuristic = test_build_result['auto-build-setup'][2].heuristic_id
    static_libs = test_build_result['executables-build']['static-libs']

    append_to_report(
        outdir,
        f'build success: {build_heuristic} :: {test_dir} :: {static_libs}')
    print("%s : %s : %s" %
          (test_build_result['auto-build-setup'][2].heuristic_id, test_dir,
           test_build_result['executables-build']['static-libs']))

  # For each of the auto generated build scripts identify the
  # static libraries resulting from the build.
  refine_static_libs(build_results)

  # Stage 2: perform program analysis to extract data to be used for
  # harness generation.
  build_empty_fuzzers(build_results)

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
  heuristics_passed = {}
  folders_with_results = set()
  print(f'Going through {len(build_results)} build results to generate fuzzers')
  for test_dir, build_result in build_results.items():
    # Skip if build suggestion did not work with an empty fuzzer.
    build_heuristic_id = build_result['auto-build-setup'][2].heuristic_id

    print(f'Checking build heuristic: {build_heuristic_id}')
    if build_result.get('base-fuzz-build', False) is False:
      print('Build failed, skipping')
      continue

    # Run Fuzz Introspector on the target
    print('Running introspector build')
    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      shutil.rmtree(INTROSPECTOR_OSS_FUZZ_DIR)

    _, fuzzer_build_cmd = run_introspector_on_dir(build_results, test_dir)

    if os.path.isdir(INTROSPECTOR_OSS_FUZZ_DIR):
      print("Introspector build success")
    else:
      print("Failed to get introspector results")

    # Identify the relevant functions
    introspector_report = load_introspector_report()
    if introspector_report is None:
      continue

    #sys.exit(0)
    func_count = len(
        introspector_report["MergedProjectProfile"]["all-functions"])
    print(f'Found a total of {func_count} functions.')
    append_to_report(outdir, 'Introspector analysis done')

    print("Test dir: %s" % (str(test_dir)))
    all_header_files = get_all_header_files(get_all_files_in_path(test_dir))

    append_to_report(outdir, f'Total functions in {test_dir} : {func_count}')

    if disable_fuzzgen:
      continue

    # At this point we have:
    # - A list of functions from the introspector analyses
    # - A list of build scripts that can auto-build the project
    # - A list of the static libraries created during the compilation process
    # We can now proceed to apply heuristics that use this data to generate
    # fuzzing harnesses and build scripts for these harnesses.
    heuristics_to_apply = [
        FuzzerGenHeuristic4, FuzzerGenHeuristic3, FuzzerGenHeuristic2,
        FuzzerGenHeuristic1
    ]
    idx = 0
    print(f'Running target functions through {len(heuristics_to_apply)}' +
          ' fuzzer harness generation heuristics')
    for heuristic_class in heuristics_to_apply:

      # Initialize heuristic with the fuzz introspector data
      heuristic = heuristic_class(introspector_report, all_header_files,
                                  test_dir)
      print(f'Applying {heuristic.name}')

      heuristic.github_url = github_url
      harness_builds_to_validate = generate_harness_intrinsics(
          heuristic, build_results, test_dir, fuzzer_build_cmd)

      # Build the fuzzer for each project
      print("Fuzzer harnesses to evaluate: %d" %
            (len(harness_builds_to_validate)))
      for result_to_validate in harness_builds_to_validate:
        print('Evaluating harness')
        fuzzer_intrinsics = result_to_validate['fuzzer-intrinsics']
        # Make a directory and store artifacts there
        evaluate_heuristic(test_dir, result_to_validate, fuzzer_intrinsics,
                           heuristics_passed, idx, disable_fuzz_build_and_test,
                           folders_with_results, outdir)
        idx += 1

  if disable_fuzzgen:
    return

  # Show those that succeeded.
  for hp in heuristics_passed:
    print("Success: %s" % (hp))

  print("Auto-generated fuzzers:")
  if outdir:
    bash_script = "#!/bin/bash\n"
    for folder in folders_with_results:
      src_folder = folder  #"/".join(folder.split("/")[:-1])
      src_folder_base = os.path.basename(src_folder)

      dst_folder = os.path.join(outdir, src_folder_base)
      print("Copying: %s to %s" % (folder, dst_folder))
      if folder == '/src':
        print("Skipping")
        continue
      if folder.count('/') < 2:
        print("Skipping 2")
        continue
      if not os.path.isdir(outdir):
        os.mkdir(outdir)

      exec_command = os.path.join(dst_folder, folder.split("/")[-1])
      bash_script += exec_command + " -max_total_time=10\n"
    print("-" * 45)
    print(bash_script)


def parse_commandline():
  """Commandline parser."""
  parser = argparse.ArgumentParser()
  parser.add_argument('repo', help="Github url of target")
  parser.add_argument('--disable-build-test',
                      action='store_true',
                      help='disables')
  parser.add_argument(
      '--disable-fuzzgen',
      action='store_true',
      help='disables auto generation of fuzzers, only build will run.')
  parser.add_argument('--disable-fuzz-build-and-test',
                      action='store_true',
                      help='disables building and testing of fuzzers')
  parser.add_argument("--out", "-o", help="Directory to store successful runs")
  parser.add_argument('--targets-per-heuristic',
                      '-t',
                      help='Targets per heuristic.',
                      type=int,
                      default=5)
  return parser


def main():
  global MAX_FUZZ_PER_HEURISTIC

  parser = parse_commandline()
  args = parser.parse_args()

  append_to_report(args.out, f'Analysing: {args.repo}')
  MAX_FUZZ_PER_HEURISTIC = args.targets_per_heuristic

  auto_generate(args.repo, args.disable_build_test, args.disable_fuzzgen,
                args.disable_fuzz_build_and_test, args.out)


if __name__ == "__main__":
  main()
