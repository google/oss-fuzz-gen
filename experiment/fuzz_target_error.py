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
"""
Helper class for fuzz target semantic errors.
"""
import re
from typing import Optional


class SemanticError:
  """Fuzz target semantic errors."""
  NO_SEMANTIC_ERR = 'NO_SEMANTIC_ERR'
  LOG_MESS_UP = 'LOG_MESS_UP'
  FP_NEAR_INIT_CRASH = 'FP_NEAR_INIT_CRASH'
  FP_TARGET_CRASH = 'FP_TARGET_CRASH'
  FP_MEMLEAK = 'FP_MEMLEAK'
  FP_OOM = 'FP_OOM'
  FP_TIMEOUT = 'FP_TIMEOUT'
  NO_COV_INCREASE = 'NO_COV_INCREASE'

  # Regex for extract crash symptoms.
  # Matches over 18 types of ASAN errors symptoms
  #  e.g. ERROR: AddressSanitizer: attempting use-after-free on xxx
  #  e.g. ERROR: AddressSanitizer: attempting stack-overflow on xxx
  #  e.g. ERROR: AddressSanitizer: attempting negative-size-param on xxx
  # Full list here: https://github.com/occia/fuzzdrivergpt/blob/35b0e957a61be8bd506017cda621a50e75f5acdb/validation/libVR.py#L466-L485.
  SYMPTOM_ASAN = re.compile(r'ERROR: AddressSanitizer: (.*)\n')
  # Matches 'ERROR: libFuzzer: timeout after xxx'
  SYMPTOM_LIBFUZZER = re.compile(r'ERROR: libFuzzer: (.*)\n')

  @classmethod
  def extract_symptom(cls, fuzzlog: str) -> str:
    """Extracts crash symptom from fuzzing logs."""
    match = cls.SYMPTOM_ASAN.match(fuzzlog)
    if match:
      return f'ASAN-{match.group(0)}'

    match = cls.SYMPTOM_LIBFUZZER.match(fuzzlog)
    if match:
      return f'libFuzzer-{match.group(0)}'

    return ''

  def __init__(self,
               err_type: str,
               crash_symptom: str = '',
               crash_stacks: Optional[list[list[str]]] = None):
    self.type = err_type
    self.crash_symptom = crash_symptom
    self.crash_stacks = crash_stacks if crash_stacks else []

  def _get_error_desc(self) -> str:
    """Returns one sentence error description used in fix prompt."""
    if self.type == self.LOG_MESS_UP:
      # TODO(happy-qop): Add detailed description for this error type.
      return 'Overlong fuzzing log.'
    if self.type == self.FP_NEAR_INIT_CRASH:
      return (f'Fuzzing crashed immediately at runtime ({self.crash_symptom})'
              ', indicating fuzz target code for invoking the function under'
              ' test is incorrect or unrobust.')
    if self.type == self.FP_TARGET_CRASH:
      return (f'Fuzzing has crashes ({self.crash_symptom}) caused by fuzz '
              'target code, indicating its usage for the function under '
              'test is incorrect or unrobust.')
    if self.type == self.FP_MEMLEAK:
      return ('Memory leak detected, indicating some memory was not freed '
              'by the fuzz target.')
    if self.type == self.FP_OOM:
      return ('Out-of-memory error detected, suggesting memory leak in the'
              ' fuzz target.')
    if self.type == self.FP_TIMEOUT:
      return ('Fuzz target timed out at runtime, indicating its usage for '
              'the function under test is incorrect or unrobust.')
    if self.type == self.NO_COV_INCREASE:
      # TODO(dongge): Append the implementation of the function under test.
      return ('Low code coverage, indicating the fuzz target ineffectively '
              'invokes the function under test.')

    return ''

  def _get_error_detail(self) -> list[str]:
    """Returns detailed error description used in fix prompt."""
    if self.type not in [
        self.FP_NEAR_INIT_CRASH, self.FP_TARGET_CRASH, self.FP_TIMEOUT
    ]:
      return []

    detail = ['Crash stacks:']
    for index, stack in enumerate(self.crash_stacks):
      detail.append(f'Stack {index}:')
      detail.extend(stack)
    return detail

  def get_error_info(self) -> tuple[str, list[str]]:
    return self._get_error_desc(), self._get_error_detail()

  @property
  def has_err(self) -> bool:
    return self.type != self.NO_SEMANTIC_ERR
