"""The abstract base class for tools used by LLM agents to gather information
or perform specific actions."""
from abc import ABC, abstractmethod
from typing import Any


class BaseTool(ABC):
  """Abstract base class for tools used by LLM agents to interact with various
  environments or perform actions. Provides a common interface for creating
  tool-specific guides and executing commands."""

  def __init__(self, name: str = '') -> None:
    # The name of the tool.
    self.name: str = name or self.__class__.__name__

  @abstractmethod
  def tutorial(self) -> str:
    """Constructs a guide for LLM, e.g., based on self.command_usages."""

  @abstractmethod
  def execute(self, command: str) -> Any:
    """Executes tool based on the command."""
