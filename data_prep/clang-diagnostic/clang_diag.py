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
"""Interested classes defined in Diagnostic.td"""
from typing import Optional


class DiagGroup:
  """
  Represents a DiagGroup class:
  class DiagGroup<string Name, list<DiagGroup> subgroups = []> {
    string GroupName;
    list<DiagGroup> SubGroups;
    string CategoryName;
    code Documentation;
  }
  """

  def __init__(self, category_name: str, documentation: str, group_name: str,
               sub_groups: list[str]):
    self.category_name = category_name
    self.documentation = documentation
    self.group_name = group_name
    self.sub_groups = sub_groups

  def __str__(self):
    return self.group_name


class TextSubstitution:
  """
  Represents a TextSubstitution class:
  class TextSubstitution<string Text> {
    string Substitution;
    string Component;
    string CategoryName;
    bit Deferrable;
  }
  """

  def __init__(self, category_name: str, component: str, substitution: str):
    self.category_name = category_name
    self.component = component
    self.substitution = substitution

  def __str__(self):
    return self.substitution


class Diagnostic:
  """
  Represents a Diagnostic class,
  also holds the diag regex and number of captured arguments:
  class Diagnostic<string text, DiagClass DC, Severity defaultmapping> {
    string         Component;
    string         Text;
    DiagClass      Class;
    SFINAEResponse SFINAE;
    bit            AccessControl;
    bit            WarningNoWerror;
    bit            ShowInSystemHeader;
    bit            ShowInSystemMacro;
    bit            Deferrable;
    Severity       DefaultSeverity;
    DiagGroup      Group;
    string         CategoryName;
  }
  """

  def __init__(self,
               category_name: str,
               diag_class: str,
               component: str,
               default_severity: str,
               group: Optional[DiagGroup],
               sfinae: str,
               text: str,
               regex: str = '',
               args_count: int = 0):
    self.category_name = category_name
    self.diag_class = diag_class
    self.component = component
    self.default_severity = default_severity
    self.group = group
    self.sfinae = sfinae
    self.text = text
    self.regex = regex
    self.args_count = args_count

  def __str__(self):
    return self.text
