"""The abstract base class for stages in fuzzing pipeline."""
import argparse
from abc import ABC, abstractmethod
from typing import Optional

import logger
from agent.base_agent import BaseAgent
from common.cloud_builder import CloudBuilder
from results import Result


class BaseStage(ABC):
  """The abstract base class for stages in fuzzing pipeline."""

  def __init__(self,
               args: argparse.Namespace,
               agents: Optional[list[BaseAgent]] = None) -> None:
    self.args = args
    self.agents: list[BaseAgent] = agents or []
    self.logger = logger.get_logger_adapter()

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

  def _execute_agent_cloud(self, agent: BaseAgent,
                           result_history: list[Result]) -> Result:
    """Executes agent in cloud build."""
    cloud_builder = CloudBuilder(self.args)
    pickle_dir = result_history[-1].work_dirs.pickles
    result = cloud_builder.run(agent, result_history, pickle_dir)
    return result

  @abstractmethod
  def execute(self, result_history: list[Result]) -> Result:
    """Executes the stage-specific actions using agents."""
