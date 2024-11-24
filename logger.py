"""A note-taker module to write experiment logs and result files. It attaches
extra key info to logs and results (such as trial ID, function signature,
project) to help identify log during debugging and result tracking."""
import json
import logging
import os
from typing import Mapping

from results import Result

FINAL_RESULT_JSON = 'result.json'


class CustomLoggerAdapter(logging.LoggerAdapter):
  """A note-taker to log and record experiment status, key info, and final
  results."""

  def process(self, msg, kwargs):
    # Combine 'extra' dictionaries and modify the message
    kwargs['extra'] = {**(self.extra or {}), **(kwargs.get('extra') or {})}
    return msg, kwargs

  def write_to_file(self, file_path: str, file_content: str) -> None:
    """Writes the |file_content| into a local |file_path|."""
    with open(file_path, 'w') as file:
      file.writelines(file_content)

  def write_fuzz_target(self, result: Result) -> None:
    """Writes fuzz target."""
    fuzz_target_path = os.path.join(result.work_dirs.fuzz_targets,
                                    f'{result.trial:02d}.fuzz_target')
    self.write_to_file(fuzz_target_path, result.fuzz_target_source)

  def write_build_script(self, result: Result) -> None:
    """Writes build script."""
    build_script_path = os.path.join(result.work_dirs.fuzz_targets,
                                     f'{result.trial:02d}.build_script')
    self.write_to_file(build_script_path, result.build_script_source)

  def write_result(self, result_status_dir: str, result: Result) -> None:
    """Writes the final result into JSON for report generation."""
    trial_result_dir = os.path.join(result_status_dir, f'{result.trial:02d}')
    os.makedirs(trial_result_dir, exist_ok=True)
    with open(os.path.join(trial_result_dir, FINAL_RESULT_JSON), 'w') as f:
      json.dump(result.to_dict(), f)

  def write_chat_history(self, result: Result) -> None:
    """Writes fuzz target."""
    # TODO(dongge): Find a proper way to write this.
    trial_result_dir = os.path.join(result.work_dirs.status,
                                    f'{result.trial:02d}')
    os.makedirs(trial_result_dir, exist_ok=True)
    chat_history_path = os.path.join(trial_result_dir, 'log.txt')
    chat_history = '\n'.join(
        f'{agent_name}\n{chat_history}\n'
        for agent_name, chat_history in result.chat_history.items())
    self.write_to_file(chat_history_path, chat_history)


def debug(msg: object,
          *args: object,
          trial: int,
          exc_info=None,
          stack_info: bool = False,
          stacklevel: int = 1,
          extra: Mapping[str, object] | None = None,
          **kwargs: object) -> None:
  return get_trial_logger(trial=trial).debug(msg,
                                             *args,
                                             exc_info=exc_info,
                                             stack_info=stack_info,
                                             stacklevel=stacklevel,
                                             extra=extra,
                                             **kwargs)


def info(msg: object,
         *args: object,
         trial: int,
         exc_info=None,
         stack_info: bool = False,
         stacklevel: int = 1,
         extra: Mapping[str, object] | None = None,
         **kwargs: object) -> None:
  return get_trial_logger(trial=trial).info(msg,
                                            *args,
                                            exc_info=exc_info,
                                            stack_info=stack_info,
                                            stacklevel=stacklevel,
                                            extra=extra,
                                            **kwargs)


def warning(msg: object,
            *args: object,
            trial: int,
            exc_info=None,
            stack_info: bool = False,
            stacklevel: int = 1,
            extra: Mapping[str, object] | None = None,
            **kwargs: object) -> None:
  return get_trial_logger(trial=trial).warning(msg,
                                               *args,
                                               exc_info=exc_info,
                                               stack_info=stack_info,
                                               stacklevel=stacklevel,
                                               extra=extra,
                                               **kwargs)


def error(msg: object,
          *args: object,
          trial: int,
          exc_info=None,
          stack_info: bool = False,
          stacklevel: int = 1,
          extra: Mapping[str, object] | None = None,
          **kwargs: object) -> None:
  return get_trial_logger(trial=trial).error(msg,
                                             *args,
                                             exc_info=exc_info,
                                             stack_info=stack_info,
                                             stacklevel=stacklevel,
                                             extra=extra,
                                             **kwargs)


def get_trial_logger(name: str = __name__,
                     trial: int = 0,
                     level=logging.DEBUG) -> CustomLoggerAdapter:
  """Sets up or retrieves a thread-local CustomLoggerAdapter for each thread."""
  logger = logging.getLogger(name)
  if not logger.handlers:
    formatter = logging.Formatter(
        fmt=('%(asctime)s [Trial ID: %(trial)02d] %(levelname)s '
             '[%(module)s.%(funcName)s]: %(message)s'),
        datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False

  return CustomLoggerAdapter(logger, {'trial': trial})
