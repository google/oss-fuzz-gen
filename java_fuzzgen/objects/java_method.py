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
"""Object class to store details of each java methods."""

from typing import Dict


class JAVAMETHOD:
  """Class holder for Java method data"""

  def __init__(self, func_elem: Dict):
    self.data_dict = func_elem

  @property
  def full_qualified_name(self) -> str:
    return self.data_dict['functionName']

  @property
  def name(self) -> str:
    return self.full_qualified_name.split('].')[-1].split('(')[0]

  @property
  def full_qualified_class_name(self) -> str:
    return self.full_qualified_name.split('].')[0].split('[')[1]

  @property
  def class_name(self) -> str:
    return self.full_qualified_class_name.split(".")[-1]

  @property
  def arg_count(self) -> int:
    return self.data_dict['argCount']

  @property
  def is_constructor(self) -> bool:
    return "<init>" in self.name

  @property
  def is_public(self) -> bool:
    return self.data_dict['JavaMethodInfo']['classPublic'] and self.data_dict[
        'JavaMethodInfo']['public']

  @property
  def is_concrete(self) -> bool:
    return self.data_dict['JavaMethodInfo']['classConcrete'] and self.data_dict[
        'JavaMethodInfo']['concrete']

  @property
  def is_getter_setter(self) -> bool:
    return self.name.startswith("set") or self.name.startswith(
        "get") or self.name.startswith("is")

  @property
  def is_test(self) -> bool:
    test_name = ["test", "demo", "jazzer"]
    for name in test_name:
      if name in self.full_qualified_name:
        return True

    return False

  @property
  def is_simple_arg_only(self) -> bool:
    """Check if the method requires simple arguments only."""
    simple_args = [
        "boolean", "byte", "char", "short", "int", "long", "float", "double",
        "boolean[]", "byte[]", "char[]", "short[]", "int[]", "long[]",
        "float[]", "double[]", "java.lang.string"
    ]
    for arg_type in self.data_dict['argTypes']:
      if arg_type.lower() not in simple_args:
        return False

    return True

  def is_skip(self,
              max_arg_count: int = 20,
              simple_arg_only: bool = False) -> bool:
    """Check if this method should be skipped."""
    if not self.is_public or not self.is_concrete or self.is_getter_setter:
      return True
    if self.arg_count == 0 or self.arg_count > max_arg_count or self.is_test:
      return True

    if simple_arg_only:
      return not self.is_simple_arg_only

    return False
