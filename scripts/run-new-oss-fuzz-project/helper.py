"""Module for running OFG on multiple new OSS-Fuzz projects. This module
must be run from the base of OFG."""
import os
import shutil
import subprocess
import sys

source_dir = sys.argv[1]

TARGET_OSS_FUZZ = 'work/oss-fuzz'

projects_to_exec = ''
for empty_oss_fuzz in os.listdir(source_dir):
  dst = os.path.join(TARGET_OSS_FUZZ, 'projects', empty_oss_fuzz)
  if os.path.isdir(dst):
    shutil.rmtree(dst)

  shutil.copytree(os.path.join(source_dir, empty_oss_fuzz), dst)
  projects_to_exec += empty_oss_fuzz + ' '

# Launch the runner
cmd = f'scripts/run-new-oss-fuzz-project/run-project.sh {projects_to_exec}'

# Call with shell to ensure we have the right environment.
subprocess.check_call(cmd, shell=True)
