"""A note-taker module to write experiment logs and result files. It attaches
extra key info to logs and results (such as trial ID, function signature,
project) to help identify log during debugging and result tracking."""
import json
import logging
import os

from results import Result

FINAL_RESULT_JSON = 'result.json'

_trial_logger = None


class CustomLoggerAdapter(logging.LoggerAdapter):
  """A note-taker to log and record experiment status, key info, and final
  results."""

  def write_to_file(self, file_path: str, file_content: str) -> None:
    """Writes the |file_content| into a local |file_path|."""
    with open(file_path, 'w') as file:
      file.writelines(file_content)

  def write_fuzz_target(self, result: Result) -> None:
    """Writes fuzz target."""
    fuzz_target_path = os.path.join(result.work_dirs.raw_targets,
                                    f'{result.trial:02d}.fuzz_target')
    self.write_to_file(fuzz_target_path, result.fuzz_target_source)

  def write_build_script(self, result: Result) -> None:
    """Writes build script."""
    build_script_path = os.path.join(result.work_dirs.raw_targets,
                                     f'{result.trial:02d}.build_script')
    self.write_to_file(build_script_path, result.build_script_source)

  def write_result(self, result_status_dir: str, result: Result) -> None:
    """Writes the final result into JSON for report generation."""
    trial_result_dir = os.path.join(result_status_dir, f'{result.trial:02d}')
    os.makedirs(trial_result_dir, exist_ok=True)
    with open(os.path.join(trial_result_dir, FINAL_RESULT_JSON), 'w') as f:
      json.dump(result.to_dict(), f)


def get_trial_logger(name: str = __name__,
                     trial: int = 0,
                     level=logging.INFO) -> CustomLoggerAdapter:
  """Sets up or retrieves the singleton instance of CustomLoggerAdapter."""
  global _trial_logger
  if _trial_logger is None:
    logger = logging.getLogger(name)
    if not logger.handlers:  # Avoid adding duplicated handlers
      formatter = logging.Formatter(
          fmt=('%(asctime)s [Trial ID: %(trial)02d] %(levelname)s '
               '[%(module)s.%(funcName)s]: %(message)s'),
          datefmt='%Y-%m-%d %H:%M:%S')
      handler = logging.StreamHandler()
      handler.setFormatter(formatter)
      logger.addHandler(handler)
      logger.setLevel(level)
    _trial_logger = CustomLoggerAdapter(logger, {'trial': trial})
  return _trial_logger
