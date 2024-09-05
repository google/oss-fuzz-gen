"""General utility functions."""
import logging
import os
import pickle
from typing import Any


def serialize_to_pickle(variable: Any, pickle_path: str = '') -> str:
  """Serializes |variable| to a pickle file under |path_prefix| and returns
  the file path."""
  path_prefix = os.path.dirname(pickle_path)
  os.makedirs(path_prefix, exist_ok=True)
  with open(pickle_path, 'wb') as f:
    pickle.dump(variable, f)
  logging.info('Serialized %s to %s', variable, pickle_path)
  return pickle_path


def deserialize_from_pickle(pickle_path: Any) -> Any:
  """Serializes |variable| to a pickle file under |path_prefix| and returns
  the file path."""
  with open(pickle_path, 'rb') as f:
    obj = pickle.load(f)
  logging.info('Deserialized %s to %s', pickle_path, obj)
  return obj
