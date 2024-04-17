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

from typing import Dict

class JAVA_METHOD:
  """Class holder for Java method data"""

  def __init__(self, func_elem: Dict):
    self.data_dict = func_elem

  @property
  def full_qualified_name(self) -> str:
    return self.data_dict['functionName']

  @property
  def name(self) -> str:
    return self.data_dict['functionName'].split('].')[-1].split('(')[0]

  @property
  def arg_count(self) -> int:
    return self.data_dict['argCount']

  @property
  def is_constructor(self) -> bool:
    return "<init>" in self.name

  @property
  def is_public(self) -> bool:
    return self.data_dict['JavaMethodInfo']['classPublic'] and self.data_dict['JavaMethodInfo']['public']

  @property
  def is_concrete(self) -> bool:
    return self.data_dict['JavaMethodInfo']['classConcrete'] and self.data_dict['JavaMethodInfo']['concrete']

  @property
  def is_getter_setter(self) -> bool:
    return self.name.startswith("set") or self.name.startswith("get") or self.name.startswith("is")

  @property
  def is_test(self) -> bool:
    return "test" in self.full_qualified_name or "demo" in self.full_qualified_name or "jazzer" in self.full_qualified_name

  @property
  def is_skip(self) -> bool:
    return self.is_constructor or not self.is_public or not self.is_concrete or self.is_getter_setter or self.arg_count == 0 or self.is_test
