"""Writing to the fuzz target and build script."""
import logging

from results import Result
from stage.base_stage import BaseStage

logging.basicConfig(level=logging.DEBUG,
                    format=('%(asctime)s [PID: %(process)d] %(levelname)s '
                            '[%(module)s.%(funcName)s]: %(message)s'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class WritingStage(BaseStage):
  """Writing to the fuzz target and build script."""

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
