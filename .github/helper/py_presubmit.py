#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Pre submit checks in same style as OSS-Fuzz"""

import os
import sys
import subprocess


def do_checks(changed_files):
  """Runs all presubmit checks. Returns False if any fails."""
  checks = [
      check_license,
  ]
  return all([check(changed_files) for check in checks])

_CHECK_LICENSE_FILENAMES = ['Dockerfile']
_CHECK_LICENSE_EXTENSIONS = [
    '.bash',
    '.Dockerfile',
    '.go',
    '.h',
    '.htm',
    '.html',
    '.java',
    '.proto',
    '.py',
    '.rs',
    '.sh',
    '.ts',
]
THIRD_PARTY_DIR_NAME = 'third_party'

_LICENSE_STRING = 'http://www.apache.org/licenses/LICENSE-2.0'


def check_license(paths):
  """Validates license header."""
  if not paths:
    return True

  success = True
  for path in paths:
    path_parts = str(path).split(os.sep)
    if any(path_part == THIRD_PARTY_DIR_NAME for path_part in path_parts):
      continue
    filename = os.path.basename(path)
    extension = os.path.splitext(path)[1]
    if (filename not in _CHECK_LICENSE_FILENAMES and
        extension not in _CHECK_LICENSE_EXTENSIONS):
      continue

    with open(path) as file_handle:
      if _LICENSE_STRING not in file_handle.read():
        print('Missing license header in file %s.' % str(path))
        success = False

  return success


def bool_to_returncode(success):
  """Returns 0 if |success|. Otherwise returns 1."""
  if success:
    print('Success.')
    return 0

  print('Failed.')
  return 1

def get_all_files():
  """Returns a list of absolute paths of files in this repo."""
  get_all_files_command = ['git', 'ls-files']
  output = subprocess.check_output(get_all_files_command).decode().splitlines()
  return [os.path.abspath(path) for path in output if os.path.isfile(path)]


def main():
    relevant_files = get_all_files()
    success = do_checks(relevant_files)
    return bool_to_returncode(success)


if __name__ == '__main__':
  sys.exit(main())
