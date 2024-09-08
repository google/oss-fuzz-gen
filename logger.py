"""A module to write logs and files."""
import json
import logging
import os

from google.cloud import logging as cloud_logging
from google.cloud.logging.handlers import CloudLoggingHandler

from results import Result

RESULT_JSON = 'result.json'


class Logger(logging.Logger):

  def __init__(self, name: str, trial: int = 0) -> None:
    super().__init__(name)
    self.trial = trial

    log_format = ('%(asctime)s [Trial ID: %(trial)02d] %(levelname)s '
                  '[%(module)s.%(funcName)s]: %(message)s')
    formatter = logging.Formatter(fmt=log_format, datefmt='%Y-%m-%d %H:%M:%S')

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    self.addHandler(console_handler)

    self.setLevel(logging.DEBUG)

  def _add_context(self, msg, **kwargs):
    # Automatically add extra context to log messages
    extra = kwargs.get('extra', {})
    extra['trial'] = self.trial
    kwargs['extra'] = extra
    return msg, kwargs

  def info(self, msg, *args, **kwargs):
    msg, kwargs = self._add_context(msg, **kwargs)
    super().info(msg, *args, **kwargs)

  def warning(self, msg, *args, **kwargs):
    msg, kwargs = self._add_context(msg, **kwargs)
    super().warning(msg, *args, **kwargs)

  def error(self, msg, *args, **kwargs):
    msg, kwargs = self._add_context(msg, **kwargs)
    super().error(msg, *args, **kwargs)

  def write_result(self, result_status_dir: str, result: Result) -> None:
    """Writes the final result into JSON for report generation."""
    with open(os.path.join(result_status_dir, 'result.json'), 'w') as f:
      json.dump(result.to_dict(), f)


logger = Logger(__name__)
