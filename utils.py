"""General utility functions."""
import logging
import os
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
