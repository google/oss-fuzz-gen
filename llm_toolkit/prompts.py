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
LLM prompt definitions.
"""

import json
from abc import abstractmethod
from typing import Any


class Prompt:
  """Base prompt."""

  def __init__(self, initial=None):
    """Constructor."""

  @abstractmethod
  def append(self, text: str) -> None:
    """Appends to the formatted prompt."""

  @abstractmethod
  def get(self) -> Any:
    """Gets the final formatted prompt."""

  @abstractmethod
  def create_prompt_piece(self, content: str, role: str) -> Any:
    """Creates prompt based on the |content| and |role|."""

  @abstractmethod
  def add_priming(self, priming_content: str) -> None:
    """Adds |priming_content| to prompt."""

  @abstractmethod
  def add_problem(self, problem_content: str) -> None:
    """Adds |problem_content| to prompt."""

  @abstractmethod
  def add_solution(self, solution_content: str) -> None:
    """Adds |solution_content| to prompt."""

  @abstractmethod
  def save(self, location: str) -> None:
    """Saves the prompt to a filelocation."""


class TextPrompt(Prompt):
  """Text-style prompts."""

  def __init__(self, initial=None):
    if not initial:
      initial = ''

    self._text = initial

  def append(self, text: str) -> None:
    """Gets the final formatted prompt."""
    self._text += text

  def get(self) -> Any:
    """Gets the final formatted prompt."""
    return self._text

  def add_priming(self, priming_content: str) -> None:
    """Constructs the prompt priming in the required format."""
    self._text += f'{priming_content}\n'

  def add_problem(self, problem_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._text += f'{problem_content}\n'

  def add_solution(self, solution_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._text += f'{solution_content}\n'

  def create_prompt_piece(self, content: str, role: str) -> Any:
    """Returns a prompt piece in the format wanted by Google."""
    # Ignore role, just return content
    del role
    # TODO(Dongge): Use role as XML tags.
    return content

  def save(self, location: str) -> None:
    """Saves the prompt to a filelocation."""
    with open(location, 'w+') as prompt_file:
      prompt_file.write(self.get())


class OpenAIPrompt(Prompt):
  """OpenAI style structured prompt."""

  def __init__(self, initial=None):
    if not initial:
      initial = []

    self._prompt = initial

  def get(self) -> Any:
    """Gets the final formatted prompt."""
    return self._prompt

  def add_priming(self, priming_content: str) -> None:
    """Constructs the prompt priming in the required format."""
    self._prompt.append({
        'role': 'system',
        'content': priming_content,
    })

  def add_problem(self, problem_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt.append({
        'role': 'user',
        'content': problem_content,
    })

  def add_solution(self, solution_content: str) -> None:
    """Constructs the prompt problem in the required format."""
    self._prompt.append({
        'role': 'assistant',
        'content': solution_content,
    })

  def create_prompt_piece(self, content: str, role: str) -> Any:
    """Returns a prompt piece in the format wanted by OpenAI."""
    # TODO(mihaimaruseac): We might want to consider stripping the XML tags
    # here? The roles kind of simulate them.
    return [{'role': role, 'content': content}]

  def save(self, location: str) -> None:
    """Saves the prompt to a filelocation."""
    with open(location, 'w+') as prompt_file:
      json.dump(self._prompt, prompt_file)

  def append(self, text: str) -> None:
    """Appends to the formatted prompt."""
    self._prompt.append({
        'role': 'system',
        'content': text,
    })


class ClaudePrompt(OpenAIPrompt):
  """Claude style structured prompt."""
