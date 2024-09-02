"""Writing to the fuzz target and build script."""
import logging

from result_classes import Result
from stage.base_stage import BaseStage

logging.basicConfig(level=logging.DEBUG,
                    format=('%(asctime)s [PID: %(process)d] %(levelname)s '
                            '[%(module)s.%(funcName)s]: %(message)s'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class WritingStage(BaseStage):
  """Writing to the fuzz target and build script."""

  def _write_new_fuzz_target(self, prev_results: list[Result]) -> Result:
    """Writes a new fuzz target."""
    return self.get_agent('Prototyper').execute(prev_results)

  def _refine_given_fuzz_targets(self, prev_results: list[Result]) -> Result:
    """Writes a new fuzz target."""
    return self.get_agent('Enhancer').execute(prev_results)

  def execute(self, prev_stage_results: list[Result]) -> Result:
    if prev_stage_results and prev_stage_results[-1].fuzz_target_source:
      agent_result = self._refine_given_fuzz_targets(prev_stage_results)
    else:
      agent_result = self._write_new_fuzz_target(prev_stage_results)
    logger.debug('Writing stage completed with with result:\n%s', agent_result)
    return agent_result

  # TODO(dongge): Save logs and more info into workdir.
