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
  def declarations(self) -> list[Any]:
    """Declares the function call APIs for LLM interaction."""

  @abstractmethod
  def tutorial(self) -> str:
    """Constructs a guide for LLM, e.g., based on self.command_usages."""

  @abstractmethod
  def execute(self, command: str) -> Any:
    """Executes tool based on the command."""
