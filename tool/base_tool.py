# Copyright 2025 Google LLC
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
"""The abstract base class for tools used by LLM agents to gather information
or perform specific actions."""
import os
from abc import ABC, abstractmethod
from typing import Any

from experiment.benchmark import Benchmark

TOOL_TUTORIAL_DIR = os.path.join('prompts', 'tool')


class BaseTool(ABC):
  """Abstract base class for tools used by LLM agents to interact with various
  environments or perform actions. Provides a common interface for creating
  tool-specific guides and executing commands."""

  def __init__(self, benchmark: Benchmark, name: str = '') -> None:
    self.benchmark = benchmark
    # The name of the tool.
    self.name: str = name or self.__class__.__name__

  def _get_tutorial_file_content(self, filename: str) -> str:
    tutorial_path = os.path.join(TOOL_TUTORIAL_DIR, filename)
    with open(tutorial_path) as tool_tutorial_path:
      return tool_tutorial_path.read()

  @abstractmethod
  def tutorial(self) -> str:
    """Constructs a guide for LLM, e.g., based on self.command_usages."""

  @abstractmethod
  def execute(self, command: str) -> Any:
    """Executes tool based on the command."""
