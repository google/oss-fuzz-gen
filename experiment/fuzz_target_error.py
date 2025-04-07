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
import logging
import re
from typing import Optional

from results_wip import FuzzTargetResult

logger = logging.getLogger(__name__)


class SemanticCheckResult:
  """Fuzz target semantic check results."""
  # Regex for extract crash symptoms.
  # Matches over 18 types of ASAN errors symptoms
  #  e.g. ERROR: AddressSanitizer: attempting use-after-free on xxx
  #  e.g. ERROR: AddressSanitizer: attempting stack-overflow on xxx
  #  e.g. ERROR: AddressSanitizer: attempting negative-size-param on xxx
  # Full list here:
  # https://github.com/occia/fuzzdrivergpt/blob/35b0e957a61be8bd506017cda621a50e75f5acdb/validation/libVR.py#L466-L485.
  SYMPTOM_ASAN = re.compile(r'ERROR: AddressSanitizer: (.*)\n')
  # Matches 'ERROR: libFuzzer: timeout after xxx'
  SYMPTOM_LIBFUZZER = re.compile(r'ERROR: libFuzzer: (.*)\n')
  # E.g., matches 'SCARINESS: 10 (null-deref)'
  SYMPTOM_SCARINESS = re.compile(r'SCARINESS:\s*\d+\s*\((.*)\)\n')

  # Regex for extract crash information.
  INFO_CRASH = re.compile(r'ERROR: (.*?)(?=SUMMARY)', re.DOTALL)

  NO_COV_INCREASE_MSG_PREFIX = 'No code coverage increasement'

  @classmethod
  def extract_symptom(cls, fuzzlog: str) -> str:
    """Extracts crash symptom from fuzzing logs."""
    # Need to catch this before ASAN.
    match = cls.SYMPTOM_SCARINESS.search(fuzzlog)
    if match:
      return match.group(1).strip()

    match = cls.SYMPTOM_ASAN.search(fuzzlog)
    if match:
      return f'ASAN-{match.group(0).strip()}'

    match = cls.SYMPTOM_LIBFUZZER.search(fuzzlog)
    if match:
      return f'libFuzzer-{match.group(0).strip()}'

    return ''

  @classmethod
  def is_no_cov_increase_err(cls, error_desc: Optional[str]) -> bool:
    return (error_desc is not None) and error_desc.startswith(
        cls.NO_COV_INCREASE_MSG_PREFIX)

  @classmethod
  def extract_crash_info(cls, fuzzlog: str) -> str:
    """Extracts crash information from fuzzing logs."""
    match = cls.INFO_CRASH.search(fuzzlog)
    if match:
      return match.group(1)

    logging.warning('Failed to match crash information.')
    return ''

  def __init__(self,
               err_type: str | FuzzTargetResult,
               crash_symptom: str = '',
               crash_stacks: Optional[list[list[str]]] = None,
               crash_func: Optional[dict] = None):
    # Convert string error type to FuzzTargetResult enum if needed
    self.type = FuzzTargetResult.from_string(err_type) if isinstance(err_type, str) else err_type
    self.crash_symptom = crash_symptom
    self.crash_stacks = crash_stacks if crash_stacks else []
    self.crash_func = crash_func if crash_func else {}

  def __repr__(self) -> str:
    return (f'{self.__class__.__name__}'
            f'({", ".join(f"{k}={v!r}" for k, v in vars(self).items())})')

  def _get_error_desc(self) -> str:
    """Returns one sentence error description used in fix prompt."""
    return self.type.get_error_desc(self.crash_symptom) if self.type else ''

  def _get_error_detail(self) -> list[str]:
    """Returns detailed error description used in fix prompt."""
    if self.type not in [
        FuzzTargetResult.FP_NEAR_INIT_CRASH, 
        FuzzTargetResult.FP_TARGET_CRASH, 
        FuzzTargetResult.FP_TIMEOUT
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
    return self.type not in (FuzzTargetResult.NORM_NOT_APPLICABLE, FuzzTargetResult.NORM_NO_SEMANTIC_ERR)

  def to_dict(self):
    return {
        'has_err': self.has_err,
        'err_type': self.type.to_string() if self.type else '',
        'crash_symptom': self.crash_symptom,
        'crash_stacks': self.crash_stacks,
        'crash_func': self.crash_func,
    }
