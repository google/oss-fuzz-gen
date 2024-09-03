"""The Writing Stage class for generating and refining fuzz targets and their
corresponding build scripts. This stage is responsible for creating new fuzz
targets or improving existing ones to enhance code coverage and bug-finding
capabilities."""
import logging

from results import Result
from stage.base_stage import BaseStage

logging.basicConfig(level=logging.DEBUG,
                    format=('%(asctime)s [PID: %(process)d] %(levelname)s '
                            '[%(module)s.%(funcName)s]: %(message)s'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class WritingStage(BaseStage):
  """Handles the creation and refinement of fuzz targets and build scripts.
  Initially, this stage outputs a new fuzz target and its build script for a
  function under test. In later cycles, it uses run-time results and insights
  from previous iterations to produce a revised fuzz target.
  It leverages LLM agents to perform these tasks."""

  def _write_new_fuzz_target(self, result_history: list[Result]) -> Result:
    """Writes a new fuzz target."""
    return self.get_agent('Prototyper').execute(result_history)

  def _refine_given_fuzz_targets(self, result_history: list[Result]) -> Result:
    """Writes a new fuzz target."""
    return self.get_agent('Enhancer').execute(result_history)

  def execute(self, result_history: list[Result]) -> Result:
    if result_history and result_history[-1].fuzz_target_source:
      agent_result = self._refine_given_fuzz_targets(result_history)
    else:
      agent_result = self._write_new_fuzz_target(result_history)
    logger.debug('Writing stage completed with with result:\n%s', agent_result)
    return agent_result

  # TODO(dongge): Save logs and more info into workdir.
