"""A module to write logs and files."""
import json
import logging
import os

from results import Result

RESULT_JSON = 'result.json'

_trial_logger = None


class CustomLoggerAdapter(logging.LoggerAdapter):

  def process(self, msg, kwargs):
    kwargs['extra'] = {**kwargs.get('extra', {}), **(self.extra or {})}
    return msg, kwargs

  def write_result(self, result_status_dir: str, result: Result) -> None:
    """Writes the final result into JSON for report generation."""
    with open(os.path.join(result_status_dir, 'result.json'), 'w') as f:
      json.dump(result.to_dict(), f)


def get_logger(name: str,
               trial: int = 0,
               level=logging.DEBUG) -> CustomLoggerAdapter:
  logger = logging.getLogger(name)
  # Avoid adding duplicated handlers
  if not logger.handlers:
    formatter = logging.Formatter(
        fmt=('%(asctime)s [Trial ID: %(trial)02d] %(levelname)s '
             '[%(module)s.%(funcName)s]: %(message)s'),
        datefmt='%Y-%m-%d %H:%M:%S')

    handlers = [logging.StreamHandler()]

    for handler in handlers:
      handler.setFormatter(formatter)
      logger.addHandler(handler)

  logger.setLevel(level)
  return CustomLoggerAdapter(logger, {'trial': trial})


def set_logger_adapter(name: str = __name__,
                       trial: int = 0,
                       level=logging.INFO):
  """Sets up and returns a singleton instance of CustomLoggerAdapter with the
  specified trial."""
  global _trial_logger
  if _trial_logger is None:
    logger = get_logger(name, level)
    _trial_logger = CustomLoggerAdapter(logger, {'trial': trial})
  return _trial_logger


def get_logger_adapter():
  """Returns the singleton instance of CustomLoggerAdapter."""
  if _trial_logger is None:
    raise ValueError('Logger adapter has not been initialized.')
  return _trial_logger


# def get_logger_adapter(name: str = __name__,
#                        trial: int = 0,
#                        level=logging.DEBUG):
#   """Returns a CustomLoggerAdapter with a singleton logger."""
#   logger = get_logger(name, level)
#   return CustomLoggerAdapter(logger, {'trial': trial})
