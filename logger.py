# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A note-taker module to write experiment logs and result files. It attaches
extra key info to logs and results (such as trial ID, function signature,
project) to help identify log during debugging and result tracking."""
import json
import logging
import os
import tempfile
from typing import Mapping
from urllib.parse import urlparse

from google.cloud import logging as cloud_logging
from google.cloud import storage

from results import Result, RunResult, TrialResult

FINAL_RESULT_JSON = 'result.json'


class CustomLoggerAdapter(logging.LoggerAdapter):
  """A note-taker to log and record experiment status, key info, and final
  results."""

  def process(self, msg, kwargs):
    # Combine 'extra' dictionaries and modify the message
    kwargs['extra'] = {**(self.extra or {}), **(kwargs.get('extra') or {})}
    return msg, kwargs

  def write_to_file(self,
                    file_path: str,
                    file_content: str,
                    mode: str = 'a') -> None:
    """Writes the |file_content| into a local |file_path|."""
    with open(file_path, mode) as file:
      file.writelines(file_content)

  def write_fuzz_target(self, result: Result) -> None:
    """Writes fuzz target."""
    fuzz_target_path = os.path.join(result.work_dirs.fuzz_targets,
                                    f'{result.trial:02d}.fuzz_target')
    self.write_to_file(fuzz_target_path, result.fuzz_target_source, 'w')

  def write_build_script(self, result: Result) -> None:
    """Writes build script."""
    build_script_path = os.path.join(result.work_dirs.fuzz_targets,
                                     f'{result.trial:02d}.build_script')
    self.write_to_file(build_script_path, result.build_script_source, 'w')

  def write_result(self,
                   result_status_dir: str,
                   result: TrialResult,
                   finished: bool = False) -> None:
    """Writes the final result into JSON for report generation."""
    trial_result_dir = os.path.join(result_status_dir, f'{result.trial:02d}')
    os.makedirs(trial_result_dir, exist_ok=True)
    with open(os.path.join(trial_result_dir, FINAL_RESULT_JSON), 'w') as f:
      json.dump(result.to_dict() | {'finished': finished}, f)

  def write_chat_history(self, result: Result) -> None:
    """Writes chat history."""
    # TODO(dongge): Find a proper way to write this.
    trial_result_dir = os.path.join(result.work_dirs.status,
                                    f'{result.trial:02d}')
    os.makedirs(trial_result_dir, exist_ok=True)
    chat_history_path = os.path.join(trial_result_dir, 'log.txt')
    chat_history = '\n'.join(
        f'\n\n\n************************{agent_name}************************\n'
        f'{chat_history}\n'
        for agent_name, chat_history in result.chat_history.items())
    self.write_to_file(chat_history_path, chat_history)

  def download_gcs_file(self, local_path: str, gs_url: str) -> bool:
    """Downloads a file from Google Cloud storage to a local file."""
    parsed_url = urlparse(gs_url)
    if parsed_url.scheme != "gs":
      logging.error("URL must start with 'gs://': %s", parsed_url)

    bucket_name = parsed_url.netloc
    blob_name = parsed_url.path.lstrip("/")

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    if blob.exists():
      # Download blob to a temporary file
      with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
      blob.download_to_filename(tmp_path)
      # Append the temporary file's content to the local file
      with open(tmp_path, 'rb') as tmp_file, open(local_path,
                                                  'ab') as local_file:
        local_file.write(tmp_file.read())

      os.remove(tmp_path)
      return True
    return False

  def download_run_log(self, result: RunResult) -> None:
    local_run_log_path = os.path.join(result.work_dirs.run_logs,
                                      f'{result.trial:02d}.log')
    if self.download_gcs_file(local_run_log_path, result.run_log):
      info('Downloading cloud run log: %s to %s',
           result.log_path,
           local_run_log_path,
           trial=result.trial)
    else:
      warning('Cloud run log gsc file does not exit: %s to %s',
              result.log_path,
              local_run_log_path,
              trial=result.trial)


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
                     level: int = logging.DEBUG,
                     is_cloud: bool = False) -> CustomLoggerAdapter:
  """Sets up or retrieves a thread-local CustomLoggerAdapter for each thread."""

  if is_cloud:
    try:
      client = cloud_logging.Client()
      client.setup_logging()
    except Exception as e:
      logging.error(
          '[Trial ID: %02d] Google Cloud log client initialization failure: %s',
          trial, e)
  else:
    logging.debug('[Trial ID: %02d] Using local log.', trial)

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
