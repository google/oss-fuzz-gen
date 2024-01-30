#!/bin/bash
# Copyright 2024 Google LLC
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


## Usage:
##   bash report/docker_run.sh [benchmark_set] [frequency_label] [run_timeout]
##
##   benchmark_set determines the set of benchmarks used for the experiment.
##     The value should be the name of `benchmark-sets` directory.
##     Default: comp_benchmarks
##   frequency_label: Examples: daily, weekly, manual, etc. This is used as part of
##     Cloud Build tags and GCS report directory.
##     Default: daily
##   run_timeout: Timeout in seconds for each fuzzing target.
##     Default: 300

BENCHMARK_SET=$1
FREQUENCY_LABEL=$2
RUN_TIMEOUT=$3
# Uses python3 by default and /venv/bin/python3 for Docker containers.
PYTHON="$( [[ -x "/venv/bin/python3" ]] && echo "/venv/bin/python3" || echo "python3" )"
export PYTHON

# When running the docker container locally we need to activate the service
# account from the env variable.
# When running on GCP this step is unnecessary.
if [[ $GOOGLE_APPLICATION_CREDENTIALS != '' ]]
then
  gcloud auth activate-service-account LLM-EVAL@oss-fuzz.iam.gserviceaccount.com --key-file="${GOOGLE_APPLICATION_CREDENTIALS:?}"
fi

if [[ $BENCHMARK_SET = '' ]]
then
  BENCHMARK_SET='comp_benchmarks'
  echo "Benchmark set was not specified as the first argument. Defaulting to ${BENCHMARK_SET:?}."
fi

if [[ $FREQUENCY_LABEL = '' ]]
then
  FREQUENCY_LABEL='daily'
  echo "Frequency label was not specified as the second argument. Defaulting to ${FREQUENCY_LABEL:?}."
fi

if [[ $RUN_TIMEOUT = '' ]]
then
  RUN_TIMEOUT='300'
  echo "Run timeout was not specified as the third argument. Defaulting to ${RUN_TIMEOUT:?}."
fi

DATE=$(date '+%Y-%m-%d')
LOCAL_RESULTS_DIR='results'
# Experiment name is used to label the Cloud Builds and as part of the
# GCS directory that build logs are stored in.
#
# Example directory: 2023-12-02-daily-comp_benchmarks
EXPERIMENT_NAME="${DATE:?}-${FREQUENCY_LABEL:?}-${BENCHMARK_SET:?}"
# The subdirectory for the generated report in GCS. Use the same name as
# experiment.
# See upload_report.sh on how this is used.
GCS_REPORT_DIR=${EXPERIMENT_NAME:?}

# Generate a report and upload it to GCS
bash report/upload_report.sh "${LOCAL_RESULTS_DIR:?}" "${GCS_REPORT_DIR:?}" &
pid_report=$!

# Run the experiment
$PYTHON run_all_experiments.py \
  --benchmarks-directory "benchmark-sets/${BENCHMARK_SET:?}" \
  --run-timeout "${RUN_TIMEOUT:?}" \
  --cloud-experiment-name "${EXPERIMENT_NAME:?}" \
  --cloud-experiment-bucket 'oss-fuzz-gcb-experiment-run-logs' \
  --template-directory 'prompts/template_xml' \
  --work-dir ${LOCAL_RESULTS_DIR:?} \
  --num-samples 10 \
  --mode 'vertex_ai_code-bison-32k'

export ret_val=$?

touch /experiment_ended

# Wait for the report process to finish uploading.
wait $pid_report

# Exit with the return value of `./run_all_experiments`.
exit $ret_val
