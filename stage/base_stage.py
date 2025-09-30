"""The abstract base class for stages in fuzzing pipeline."""
import argparse
from abc import ABC, abstractmethod
from typing import Optional

import logger
from agent_graph.agents.base_agent import BaseAgent
# from common.cloud_builder import CloudBuilder # we removed this since no need to run on cloud, 
# to keep compatibility with original code, we introduce a fake cloud_builder
from results import Result

class CloudBuilder:
  """Fake cloud builder for compatibility with original code."""

  def __init__(self, args: argparse.Namespace):
    self.args = args
  
  def run(self, agent: BaseAgent, result_history: list[Result], dill_dir: str) -> Result:
    """Run the agent in cloud."""
    return agent.execute(result_history)


class BaseStage(ABC):
  """The abstract base class for stages in fuzzing pipeline."""

  def __init__(self,
               args: argparse.Namespace,
               trail: int,
               agents: Optional[list[BaseAgent]] = None,
               name: str = '') -> None:
    self.args = args
    self.trial = trail
    self.agents: list[BaseAgent] = agents or []
    self.logger = logger.get_trial_logger(trial=trail)
    self.name: str = name or self.__class__.__name__

  def __repr__(self) -> str:
    return self.__class__.__name__

  def add_agent(self, agent: BaseAgent) -> 'BaseStage':
    """Adds an agent for the stage."""
    agent.args = agent.args or self.args
    self.agents.append(agent)
    return self

  def get_agent(self, index: int = 0, agent_name: str = '') -> BaseAgent:
    """Finds the agent by its name."""
    if not agent_name:
      return self.agents[index]
    for agent in self.agents:
      if agent.name == agent_name:
        return agent
    raise RuntimeError(f'Agent {agent_name} is undefined')

  def _execute_agent_cloud(self, agent: BaseAgent,
                           result_history: list[Result]) -> Result:
    """Executes agent in cloud build."""
    cloud_builder = CloudBuilder(self.args)
    dill_dir = result_history[-1].work_dirs.dills
    result = cloud_builder.run(agent, result_history, dill_dir)
    return result

  def _execute_agent(self, agent: BaseAgent,
                     result_history: list[Result]) -> Result:
    if self.args.cloud_experiment_name:
      return self._execute_agent_cloud(agent, result_history)
    return agent.execute(result_history)

  @abstractmethod
  def execute(self, result_history: list[Result], cycle_count: int) -> Result:
    """Executes the stage-specific actions using agents."""
