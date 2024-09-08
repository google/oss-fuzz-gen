"""A module to write logs and files."""
import json
import logging
import os
from typing import Optional

from results import Result

RESULT_JSON = 'result.json'


class Logger(logging.Logger):

  def __init__(self, name: str, trial: Optional[int] = None) -> None:
    super().__init__(name)
    if trial:
      log_format = ('%(asctime)s [Trial ID: %02(trial)d] %(levelname)s '
                    '[%(module)s.%(funcName)s]: %(message)s')
    else:
      log_format = ('%(asctime)s %(levelname)s '
                    '[%(module)s.%(funcName)s]: %(message)s')
    logging.basicConfig(level=logging.DEBUG, format=log_format)

  def write_result(self, result_status_dir: str, result: Result) -> None:
    """Writes the final result into JSON for report generation."""
    with open(os.path.join(result_status_dir, 'result.json'), 'w') as f:
      json.dump(result.to_dict(), f)
