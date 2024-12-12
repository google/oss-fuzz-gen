"""The abstract base class for LLM agents in stages."""
import argparse
import codecs
import random
import re
import subprocess as sp
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import logger
import utils
from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt
from results import Result
from tool.base_tool import BaseTool


class BaseAgent(ABC):
  """The abstract base class for LLM agents in stages."""

  def __init__(self,
               trial: int,
               llm: LLM,
               tools: Optional[list[BaseTool]] = None,
               args: Optional[argparse.Namespace] = None,
               name: str = ''):
    self.trial: int = trial
    self.llm: LLM = llm
    self.tools: list[BaseTool] = tools or []
    self.args = args
    self.name: str = name or self.__class__.__name__
    self.chat_history: str = ''  # Communication history between LLM and tool.

  def __repr__(self) -> str:
    return self.__class__.__name__

  def get_tool(self, tool_name: str) -> Optional[BaseTool]:
    """Gets a tool of the agent by name."""
    for tool in self.tools:
      if tool.name == tool_name:
        return tool
    return None

  def chat_llm(self, cur_round: int, client: Any, prompt: Prompt,
               trial: int) -> Any:
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

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the XML-style tags from LLM response."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return match.group(1).strip() if match else ''

  def _filter_code(self, raw_code_block: str) -> str:
    """Filters out irrelevant lines from |raw_code_block|."""
    # TODO(dongge): Move this function to a separate module.
    # Remove markdown-style code block symbols.

    raw_code_block = codecs.decode(raw_code_block, 'unicode_escape').strip()

    filtered_lines = [
        line for line in raw_code_block.splitlines()
        if not line.strip().startswith('```')
    ]
    filtered_code_block = '\n'.join(filtered_lines)
    return filtered_code_block

  def _format_bash_execution_result(self, process: sp.CompletedProcess) -> dict:
    """Formats a prompt based on bash execution result."""
    stdout = self.llm.truncate_prompt(process.stdout)
    # TODO(dongge) Share input limit evenly if both stdout and stderr overlong.
    stderr = self.llm.truncate_prompt(process.stderr, stdout)
    return {
        'command': process.args,
        'returncode': process.returncode,
        'stdout': stdout,
        'stderr': stderr,
    }

  def _container_handle_bash_command(self, args: dict, tool: BaseTool) -> dict:
    """Handles the command from LLM with container |tool|."""
    return args | self._format_bash_execution_result(
        tool.execute(self._filter_code(args.get('command', ''))))

  def _container_handle_invalid_tool_usage(self, args: dict,
                                           tool: BaseTool) -> dict:
    """Formats a prompt to re-teach LLM how to use the |tool|."""
    return args | {
        'error': ('Malformatted function call, function name is not in '
                  f'{[decl.name for decl in tool.declarations()]}')
    }

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
