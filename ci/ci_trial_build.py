# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Entrypoint for CI into request_pr_exp. This script will get the command from
the last PR comment containing "/gcbrun" and pass it to request_pr_exp.py."""

import logging
import os
import sys

import github  # type: ignore
import request_pr_exp

TRIGGER_COMMAND = '/gcbrun'
TRIAL_BUILD_COMMAND_STR = f'{TRIGGER_COMMAND} exp '
SKIP_COMMAND_STR = f'{TRIGGER_COMMAND} skip'


def get_comments(pull_request_number):
  """Returns comments on the GitHub Pull request referenced by
  |pull_request_number|."""
  github_obj = github.Github()
  repo = github_obj.get_repo('google/oss-fuzz-gen')
  pull = repo.get_pull(pull_request_number)
  pull_comments = list(pull.get_comments())
  issue = repo.get_issue(pull_request_number)
  issue_comments = list(issue.get_comments())
  # Github only returns comments if from the pull object when a pull request is
  # open. If it is a draft, it will only return comments from the issue object.
  return pull_comments + issue_comments


def get_latest_gcbrun_command(comments):
  """Gets the last /gcbrun comment from comments."""
  for comment in reversed(comments):
    # This seems to get comments on code too.
    body = comment.body
    if body.startswith(SKIP_COMMAND_STR):
      return None
    if not body.startswith(TRIAL_BUILD_COMMAND_STR):
      continue
    if len(body) == len(TRIAL_BUILD_COMMAND_STR):
      return None
    return body[len(TRIAL_BUILD_COMMAND_STR):].strip().split(' ')
  return None


def exec_command_from_github(pull_request_number):
  """Executes the gcbrun command for trial_build.py in the most recent command
  on |pull_request_number|."""
  comments = get_comments(pull_request_number)
  command = get_latest_gcbrun_command(comments)
  if command is None:
    logging.info('Trial build not requested.')
    return None

  # Set the branch so that the trial_build builds the projects from the PR
  # branch.
  command.extend(['-p', str(pull_request_number)])
  logging.info('Command: %s.', command)
  return request_pr_exp.main(command)


def main():
  """Entrypoint for GitHub CI into trial_build.py"""
  logging.basicConfig(level=logging.INFO)
  pull_request_number = int(os.environ['PULL_REQUEST_NUMBER'])
  result = exec_command_from_github(pull_request_number)
  if result or result is None:
    return 0
  return 1


if __name__ == '__main__':
  sys.exit(main())
