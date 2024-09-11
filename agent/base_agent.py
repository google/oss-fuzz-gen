"""The abstract base class for LLM agents in stages."""
import argparse
import logging
import re
import subprocess as sp
from abc import ABC, abstractmethod
from typing import Optional

import logger
import utils
from llm_toolkit.models import LLM
from llm_toolkit.prompt_builder import DefaultTemplateBuilder
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
    self.dialog: str = ''  # Communication history between LLM and tool.

  def log(self, msg: str, level=logging.INFO):
    """Method to log messages dynamically using the logger factory."""
    agent_logger = logger.get_trial_logger()
    agent_logger.log(level, msg)

  def get_tool(self, tool_name: str) -> Optional[BaseTool]:
    """Gets a tool of the agent by name."""
    for tool in self.tools:
      if tool.name == tool_name:
        return tool
    return None

  def _parse_tag(self, response: str, tag: str) -> str:
    """Parses the XML-style tags from LLM response."""
    match = re.search(rf'<{tag}>(.*?)</{tag}>', response, re.DOTALL)
    return match.group(1).strip() if match else ''

  def _filter_code(self, raw_code_block: str) -> str:
    """Filters out irrelevant lines from |raw_code_block|."""
    # TODO(dongge): Move this function to a separate module.
    # Remove markdown-style code block symbols.
    filtered_lines = [
        line for line in raw_code_block.splitlines()
        if not line.strip().startswith('```')
    ]
    filtered_code_block = '\n'.join(filtered_lines)
    return filtered_code_block

  def _format_bash_execution_result(self, process: sp.CompletedProcess) -> str:
    return (f'<bash>\n{process.args}\n</bash>\n'
            f'<return code>\n{process.returncode}\n</return code>\n'
            f'<stdout>\n{process.stdout}\n</stdout>\n'
            f'<stderr>\n{process.stderr}\n</stderr>\n')

  def _container_handle_bash_command(self, cur_round: int, response: str,
                                     tool: BaseTool) -> Prompt:
    """Handles the command from LLM with container tool."""
    command = self._parse_tag(response, 'bash')
    if command:
      prompt_text = self._format_bash_execution_result(tool.execute(command))
    else:
      self.log(
          f'ROUND {cur_round} No BASH command from LLM response: {response}',
          logging.WARNING)
      prompt_text = ('No bash command received, Please follow the '
                     'interaction protocols:\n'
                     f'{tool.tutorial()}')
    return DefaultTemplateBuilder(self.llm, None, initial=prompt_text).build([])

  @classmethod
  def _parse_args(cls) -> argparse.Namespace:
    """Parses command line args."""
    parser = argparse.ArgumentParser(
        description='Execute agent in cloud with pickle files.')
    parser.add_argument('-a',
                        '--agent',
                        help='The pickle file path for the agent to execute.')
    parser.add_argument(
        '-rh',
        '--result-history',
        help='The pickle file path for the agent input result history.')
    parser.add_argument(
        '-rn',
        '--result-new',
        help='The pickle file path to store the agent output new result.')
    return parser.parse_args()

  @classmethod
  def cloud_main(cls) -> None:
    """Executes agent using pickle files. This is for cloud experiments."""
    args = cls._parse_args()

    agent = utils.deserialize_from_pickle(args.agent)
    result_history = utils.deserialize_from_pickle(args.result_history)
    result = agent.execute(result_history)
    utils.serialize_to_pickle(result, args.result_new)

  @abstractmethod
  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """The initial prompt of the agent."""

  @abstractmethod
  def execute(self, result_history: list[Result]) -> Result:
    """Executes the agent based on previous result."""


if __name__ == "__main__":
  # For cloud experiments.
  BaseAgent.cloud_main()
