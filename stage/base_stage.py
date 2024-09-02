"""The abstract base class for stages in fuzzing pipeline."""
import argparse
from abc import ABC, abstractmethod

from agent.base_agent import BaseAgent
from result_classes import Result


class BaseStage(ABC):
  """The abstract base class for stages in fuzzing pipeline."""

  def __init__(self, args: argparse.Namespace) -> None:
    self.args = args
    self.agents: list[BaseAgent] = []

  def add_agent(self, agent: BaseAgent) -> 'BaseStage':
    """Adds an agent for the stage."""
    agent.args = agent.args or self.args
    self.agents.append(agent)
    return self

  def get_agent(self, agent_name: str) -> BaseAgent:
    """Finds the agent by its name."""
    for agent in self.agents:
      if agent.name == agent_name:
        return agent
    raise RuntimeError(f'Agent {agent_name} is undefined')

  @abstractmethod
  def execute(self, prev_stage_results: list[Result]) -> Result:
    """Executes the stage-specific actions using agents."""
