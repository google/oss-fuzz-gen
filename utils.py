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


def retryable(exceptions=None,
              default_retries=5,
              delay_fn=lambda: random.uniform(0, 60),
              other_exceptions=None,
              default_return=None):
  """
    Decorator that retries the function on specified exceptions.
    :param exceptions: List/Set of exceptions or a dictionary of exceptions with
      custom retry counts.
    :param default_retries: Number of retries if no custom count is provided.
    :param delay_fn: Function to determine the delay between retries. Default
      is random between 0-60 seconds.
    :param default_return: The value returned if all retries fail.
    """
  exception_config = {
      exc: default_retries for exc in exceptions or {}
  } | (other_exceptions or {})
  valid_exceptions = tuple(e for e in exception_config.keys()
                           if isinstance(e, type) and issubclass(e, Exception))
  if not valid_exceptions:
    raise ValueError("No valid exception classes provided.")

  def decorator(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
      retry_count = 0
      while retry_count < default_retries:
        try:
          return func(*args, **kwargs)
        except valid_exceptions as e:  # pylint: disable=catching-non-exception
          exc_name = type(e).__name__
          retry_count += 1
          logging.info(
              'Retrying %s due to %s. Attempt %d with args=%s, kwargs=%s',
              func.__name__, exc_name, retry_count, args, kwargs)

          # Get the number of retries for this exception, or use the default
          current_retries = exception_config.get(type(e), default_retries)
          time.sleep(delay_fn(exc_name, retry_count))

          if retry_count >= current_retries:
            logging.error('Max retries reached for %s. Exiting.', exc_name)
            break
        except Exception as e:
          logging.error('Unhandled exception: %s. Exiting.', e)
          break

      # Final return after all retries failed or unhandled exception
      logging.warning('All retries failed for %s. Returning default value.',
                      func.__name__)
      return default_return

    return wrapper

  return decorator
