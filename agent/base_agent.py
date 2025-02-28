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
"""The abstract base class for LLM agents in stages."""
import argparse
import random
import re
import subprocess as sp
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import logger
import utils
from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt, OpenAIPrompt
from results import Result
from tool.base_tool import BaseTool


class BaseAgent(ABC):
  """The abstract base class for LLM agents in stages."""

  def __init__(self,
               trial: int,
               llm: LLM,
               args: argparse.Namespace,
               tools: Optional[list[BaseTool]] = None,
               name: str = ''):
    self.trial: int = trial
    self.llm: LLM = llm
    self.tools: list[BaseTool] = tools or []
    self.args = args
    self.name: str = name or self.__class__.__name__
    self.chat_history: str = ''  # Communication history between LLM and tool.
    self.max_round = self.args.agent_max_round

  def __repr__(self) -> str:
    return self.__class__.__name__

  def get_tool(self, tool_name: str) -> Optional[BaseTool]:
    """Gets a tool of the agent by name."""
    for tool in self.tools:
      if tool.name == tool_name:
        return tool
    return None

  def chat_llm(self, cur_round: int, client: Any, prompt: Prompt,
               trial: int) -> str:
    """Chat with LLM."""
    logger.info('<CHAT PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
                cur_round,
                prompt.get(),
                cur_round,
                trial=trial)
    response = self.llm.chat_llm(client=client, prompt=prompt)
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                cur_round,
                response,
                cur_round,
                trial=trial)
    return response

  def ask_llm(self, cur_round: int, prompt: Prompt, trial: int) -> str:
    """Chat with LLM."""
    logger.info('<CHAT PROMPT:ROUND %02d>%s</CHAT PROMPT:ROUND %02d>',
                cur_round,
                prompt.get(),
                cur_round,
                trial=trial)
    response = self.llm.ask_llm(prompt=prompt)
    logger.info('<CHAT RESPONSE:ROUND %02d>%s</CHAT RESPONSE:ROUND %02d>',
                cur_round,
                response,
                cur_round,
                trial=trial)
    return response

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the XML-style tags from LLM response."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return match.group(1).strip() if match else ''

  def _parse_tags(self, response: str, tag: str) -> list[str]:
    """Parses the XML-style tags from LLM response."""
    matches = re.findall(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return [content.strip() for content in matches]

  def _filter_code(self, raw_code_block: str) -> str:
    """Filters out irrelevant lines from |raw_code_block|."""
    # TODO(dongge): Move this function to a separate module.
    # Remove markdown-style code block symbols.
    filtered_lines = [
        line for line in raw_code_block.splitlines()
        if not line.strip().startswith('```')
    ]
    # Sometimes LLM returns a build script containing only comments.
    if all(line.strip().startswith('#') for line in filtered_lines):
      return ''
    filtered_code_block = '\n'.join(filtered_lines)
    return filtered_code_block

  def _format_bash_execution_result(
      self,
      process: sp.CompletedProcess,
      previous_prompt: Optional[Prompt] = None) -> str:
    """Formats a prompt based on bash execution result."""
    if previous_prompt:
      if isinstance(previous_prompt, OpenAIPrompt):
        previous_prompt_text = previous_prompt.gettext()
      else:
        previous_prompt_text = previous_prompt.get()
    else:
      previous_prompt_text = ''
    stdout = self.llm.truncate_prompt(process.stdout,
                                      previous_prompt_text).strip()
    stderr = self.llm.truncate_prompt(process.stderr,
                                      stdout + previous_prompt_text).strip()
    return (f'<bash>\n{process.args}\n</bash>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{stdout}\n</stdout>\n'
            f'<stderr>\n{stderr}\n</stderr>\n')

  def _container_handle_bash_command(self, response: str, tool: BaseTool,
                                     prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    prompt_text = ''
    for command in self._parse_tags(response, 'bash'):
      prompt_text += self._format_bash_execution_result(
          tool.execute(command), previous_prompt=prompt) + '\n'
      prompt.append(prompt_text)
    return prompt

  def _container_handle_invalid_tool_usage(self, tool: BaseTool, cur_round: int,
                                           response: str,
                                           prompt: Prompt) -> Prompt:
    """Formats a prompt to re-teach LLM how to use the |tool|."""
    logger.warning('ROUND %02d Invalid response from LLM: %s',
                   cur_round,
                   response,
                   trial=self.trial)
    prompt_text = (f'No valid instruction received, Please follow the '
                   f'interaction protocols:\n{tool.tutorial()}')
    prompt.append(prompt_text)
    return prompt

  def _container_handle_bash_commands(self, response: str, tool: BaseTool,
                                      prompt: Prompt) -> Prompt:
    """Handles the command from LLM with container |tool|."""
    prompt_text = ''
    for command in self._parse_tags(response, 'bash'):
      prompt_text += self._format_bash_execution_result(
          tool.execute(command), previous_prompt=prompt) + '\n'
      prompt.append(prompt_text)
    return prompt

  def _sleep_random_duration(
      self,
      trial: int,
      min_sec: int = 1,
      max_sec: int = 60,
  ) -> None:
    """Sleeps for a random duration between min_sec and max_sec. Agents uses
    this to avoid exceeding quota limit (e.g., LLM query frequency)."""
    duration = random.randint(min_sec, max_sec)
    logger.debug('Sleeping for %d before the next query', duration, trial=trial)
    time.sleep(duration)

  @classmethod
  def _parse_args(cls) -> argparse.Namespace:
    """Parses command line args."""
    parser = argparse.ArgumentParser(
        description='Execute agent in cloud with dill files.')
    parser.add_argument('-a',
                        '--agent',
                        help='The dill file path for the agent to execute.')
    parser.add_argument(
        '-rh',
        '--result-history',
        help='The dill file path for the agent input result history.')
    parser.add_argument(
        '-rn',
        '--result-new',
        help='The dill file path to store the agent output new result.')
    return parser.parse_args()

  @classmethod
  def cloud_main(cls) -> None:
    """Executes agent using dill files. This is for cloud experiments launched
    by cloud_builder.py. It runs `new_result = agent.execute(result_history)` in
    the same way as local experiments, except `agent` and `result_history` are
    deserialized from dill files and new_result will be serialized to share data
    with the cloud experiment requester."""
    args = cls._parse_args()

    agent = utils.deserialize_from_dill(args.agent)
    agent.llm.cloud_setup()
    result_history = utils.deserialize_from_dill(args.result_history)
    result = agent.execute(result_history)
    utils.serialize_to_dill(result, args.result_new)

  @abstractmethod
  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """The initial prompt of the agent."""

  @abstractmethod
  def execute(self, result_history: list[Result]) -> Result:
    """Executes the agent based on previous result."""


if __name__ == "__main__":
  # For cloud experiments.
  BaseAgent.cloud_main()
