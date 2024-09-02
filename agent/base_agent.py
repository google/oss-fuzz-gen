"""The abstract base class for LLM agents in stages."""
import argparse
from abc import ABC, abstractmethod
from typing import Optional

from llm_toolkit.models import LLM
from llm_toolkit.prompts import Prompt
from result_classes import Result
from tool.base_tool import BaseTool


class BaseAgent(ABC):
  """The abstract base class for LLM agents in stages."""

  def __init__(self,
               llm: LLM,
               tools: Optional[list[BaseTool]] = None,
               args: Optional[argparse.Namespace] = None,
               name: str = ''):
    self.llm: LLM = llm
    self.tools: list[BaseTool] = tools or []
    self.args = args
    self.name: str = name or self.__class__.__name__
    self.dialog: str = ''  # Communication history between LLM and tool.

  @abstractmethod
  def _initial_prompt(self, results: list[Result]) -> Prompt:
    """The initial prompt of the agent."""

  @abstractmethod
  def get_tool(self, tool_name: str) -> Optional[BaseTool]:
    """Gets a tool of the agent by name."""

  @abstractmethod
  def execute(self, prev_results: list[Result]) -> Result:
    """Executes the agent based on previous result."""
