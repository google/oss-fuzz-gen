"""The abstract base class for tools used by LLM agents."""
from abc import ABC, abstractmethod
from typing import Any


class BaseTool(ABC):

  def __init__(self, name: str = '') -> None:
    self.name: str = name or self.__class__.__name__

  @abstractmethod
  def tutorial(self) -> str:
    """Constructs a guide for LLM, e.g., based on self.command_usages."""

  @abstractmethod
  def execute(self, command: str) -> Any:
    """Executes tool based on the command."""
