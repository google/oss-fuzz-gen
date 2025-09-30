"""The Writing Stage class for generating and refining fuzz targets and their
corresponding build scripts. This stage is responsible for creating new fuzz
targets or improving existing ones to enhance code coverage and bug-finding
capabilities."""

from typing import cast

from results import BuildResult, Result
from stage.base_stage import BaseStage

class WritingStage(BaseStage):
  """Handles the creation and refinement of fuzz targets and build scripts.
  Initially, this stage outputs a new fuzz target and its build script for a
  function under test. In later cycles, it uses run-time results and insights
  from previous iterations to produce a revised fuzz target.
  It leverages LLM agents to perform these tasks."""

  def _write_new_fuzz_target(self, result_history: list[Result]) -> Result:
    """Writes a new fuzz target."""
    agent = self.get_agent()

    if self.args.cloud_experiment_name:
      return self._execute_agent_cloud(agent, result_history)
    return agent.execute(result_history)

  def _refine_given_fuzz_targets(self, result_history: list[Result]) -> Result:
    """Writes a new fuzz target."""
    agent = self.get_agent(index=1)
    if self.args.cloud_experiment_name:
      return self._execute_agent_cloud(agent, result_history)
    return agent.execute(result_history)

  def execute(self, result_history: list[Result], cycle_count: int) -> Result:
    """Executes the writing stage."""
    if result_history and result_history[-1].fuzz_target_source:
      # Execute the Enhancer agent
      # If the agent at index 0 is FunctionAnalyzer we should get agent at index 2,
      # otherwise index 1.
      if self.get_agent(index=0).name == 'FunctionAnalyzer':
        agent = self.get_agent(index=2)
      else:
        agent = self.get_agent(index=1)
    else:
      agent = self.get_agent(index=0)
      if agent.name == 'FunctionAnalyzer':
        agent_result = self._execute_agent(agent, result_history)
        self.logger.write_chat_history(agent_result, cycle_count)
        result_history.append(agent_result)

        # Then, execute the Prototyper agent to refine the fuzz target.
        agent = self.get_agent(index=1)

    agent_result = self._execute_agent(agent, result_history)
    build_result = cast(BuildResult, agent_result)

    # TODO(dongge): Save logs and more info into workdir.
    self.logger.write_fuzz_target(build_result)
    self.logger.write_build_script(build_result)
    self.logger.write_chat_history(build_result, cycle_count)
    self.logger.debug('Writing stage completed with result:\n%s', build_result)
    return build_result
