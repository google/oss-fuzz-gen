"""General utility functions."""
import logging
import os
import random
import time
from functools import wraps
from typing import Any

import dill


def serialize_to_dill(variable: Any, dill_path: str = '') -> str:
  """Serializes |variable| to a dill file under |path_prefix| and returns
  the file path."""
  path_prefix = os.path.dirname(dill_path)
  os.makedirs(path_prefix, exist_ok=True)
  with open(dill_path, 'wb') as f:
    dill.dump(variable, f)
  logging.info('Serialized %s to %s', variable, dill_path)
  return dill_path


def deserialize_from_dill(dill_path: Any) -> Any:
  """Serializes |variable| to a dill file under |path_prefix| and returns
  the file path."""
  try:
    with open(dill_path, 'rb') as f:
      obj = dill.load(f)
    logging.info('Deserialized %s to %s', dill_path, obj)
    return obj
  except FileNotFoundError as e:
    logging.error('Failed to deserialize %s: File does not exist: %s',
                  dill_path, e)
    return None


def _default_retry_delay_fn(e: Exception, n: int):
  """Delays retry by a random seconds between 0 to 1 minute."""
  del e, n
  return random.uniform(0, 60)


def retryable(exceptions=None,
              default_attempts=5,
              delay_fn=_default_retry_delay_fn,
              other_exceptions=None):
  """
    Decorator that retries the function on specified exceptions.
    :param exceptions: List/Set of exceptions or a dictionary of exceptions with
      custom retry counts.
    :param default_attempts: Number of retries if no custom count is provided.
    :param delay_fn: Function to determine the delay between retries. Default
      is random between 0-60 seconds.
    """
  exception_config = {
      exc: default_attempts for exc in exceptions or {}
  } | (other_exceptions or {})

  def decorator(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
      attempt = 1  # TODO(dongge): A separate counter for each exception.
      while True:
        try:
          return func(*args, **kwargs)
        except Exception as e:
          # Expected exceptions and their subclass.
          num_attempts = next(
              (attempts for exc_type, attempts in exception_config.items()
               if isinstance(e, exc_type)), 1)

          logging.error(
              'Exception %s on function %s(args=%s, kwargs=%s), attempt %d/%d',
              e, func.__name__, args, kwargs, attempt, num_attempts)

          if attempt >= num_attempts:
            logging.error(
                'Max attempts %d/%d reached for %s(args=%s, kwargs=%s) due to '
                '%s', attempt, num_attempts, func.__name__, args, kwargs, e)
            raise

          attempt += 1

          delay_time = delay_fn(e, attempt)
          logging.warning(
              'Delay %d seconds before re-attempting (%d/%d) function call %s('
              'args=%s, kwargs=%s)', delay_time, attempt, num_attempts,
              func.__name__, args, kwargs)
          time.sleep(delay_time)

    return wrapper

  return decorator
