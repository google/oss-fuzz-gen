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
##     Default: comparison
##   frequency_label: Examples: daily, weekly, manual, etc. This is used as part of
##     Cloud Build tags and GCS report directory.
##     Default: daily
##   run_timeout: Timeout in seconds for each fuzzing target.
##     Default: 300

# TODO(dongge): Re-write this script in Python as it gets more complex.

BENCHMARK_SET=$1
FREQUENCY_LABEL=$2
RUN_TIMEOUT=$3
SUB_DIR=$4
MODEL=$5
DELAY=$6
USE_LOCAL_INTROSPECTOR=$7
NUM_SAMPLES=$8
LLM_FIX_LIMIT=$9
VARY_TEMPERATURE=${10}
AGENT=${11}

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
  BENCHMARK_SET='comparison'
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

# The subdirectory for the generated report in GCS.
if [[ $SUB_DIR = '' ]]
then
  SUB_DIR='default'
  echo "Sub-directory was not specified as the fourth argument. Defaulting to ${SUB_DIR:?}. Please consider using sub-directory to classify your experiment."
fi

# The LLM used to generate and fix fuzz targets.
if [[ $MODEL = '' ]]
then
  MODEL='vertex_ai_gemini-1-5'
  echo "LLM was not specified as the fifth argument. Defaulting to ${MODEL:?}."
fi

# The delay used to amortize quota usage.
if [[ $DELAY = '' ]]
then
  DELAY='0'
  echo "DELAY was not specified as the sixth argument. Defaulting to ${DELAY:?}."
fi

if [[ "$USE_LOCAL_INTROSPECTOR" = "true" ]]
then
  export BENCHMARK_SET
  INTROSPECTOR_ENDPOINT="http://127.0.0.1:8080/api"
  echo "USE_LOCAL_INTROSPECTOR is enabled: ${INTROSPECTOR_ENDPOINT:?}"
  bash report/launch_local_introspector.sh
else
  INTROSPECTOR_ENDPOINT="https://introspector.oss-fuzz.com/api"
  echo "USE_LOCAL_INTROSPECTOR was not specified as the 7th argument. Defaulting to ${INTROSPECTOR_ENDPOINT:?}."
fi

#if [[ -z "${REDIRECT_OUTS}" ]]; then
#  REDIRECT_EXP_OUTPUTS=""
#else
#  
#  REDIRECT_EXP_OUTPUTS=">> $LOCAL_RESULTS_DIR/logs-from-run.txt 2>&1"
#fi

if [[ "$NUM_SAMPLES" = '' ]]
then
  NUM_SAMPLES='10'
  echo "NUM_SAMPLES was not specified as the 8th argument. Defaulting to ${NUM_SAMPLES:?}."
fi

if [[ "$LLM_FIX_LIMIT" = '' ]]
then
  LLM_FIX_LIMIT='5'
  echo "LLM_FIX_LIMIT was not specified as the 9th argument. Defaulting to ${LLM_FIX_LIMIT:?}."
else
  export LLM_FIX_LIMIT
  echo "LLM_FIX_LIMIT is set to ${LLM_FIX_LIMIT:?}."
fi

if [[ "$VARY_TEMPERATURE" = "true" ]]
then
    VARY_TEMPERATURE=(0.5 0.6 0.7 0.8 0.9)
else
    VARY_TEMPERATURE=()
fi

AGENT_ARG=""
if [[ "$AGENT" = "true" ]]; then
    AGENT_ARG="--agent"
fi

DATE=$(date '+%Y-%m-%d')
LOCAL_RESULTS_DIR='results'
# Experiment name is used to label the Cloud Builds and as part of the
# GCS directory that build logs are stored in.
#
# Example directory: 2023-12-02-daily-comparison
EXPERIMENT_NAME="${DATE:?}-${FREQUENCY_LABEL:?}-${BENCHMARK_SET:?}"
# Report directory uses the same name as experiment.
# See upload_report.sh on how this is used.
GCS_REPORT_DIR="${SUB_DIR:?}/${EXPERIMENT_NAME:?}"
# Trends report use a similarly named path.
GCS_TREND_REPORT_PATH="${SUB_DIR:?}/${EXPERIMENT_NAME:?}.json"

# Generate a report and upload it to GCS
bash report/upload_report.sh "${LOCAL_RESULTS_DIR:?}" "${GCS_REPORT_DIR:?}" "${BENCHMARK_SET:?}" "${MODEL:?}" &
pid_report=$!


# Run the experiment
$PYTHON run_all_experiments.py \
  --benchmarks-directory "benchmark-sets/${BENCHMARK_SET:?}" \
  --run-timeout "${RUN_TIMEOUT:?}" \
  --cloud-experiment-name "${EXPERIMENT_NAME:?}" \
  --cloud-experiment-bucket 'oss-fuzz-gcb-experiment-run-logs' \
  --template-directory 'prompts/template_xml' \
  --work-dir ${LOCAL_RESULTS_DIR:?} \
  --num-samples "${NUM_SAMPLES:?}" \
  --delay "${DELAY:?}" \
  --context \
  --introspector-endpoint ${INTROSPECTOR_ENDPOINT} \
  --temperature-list "${VARY_TEMPERATURE[@]}" \
  --model "$MODEL" \
  $AGENT_ARG

export ret_val=$?

touch /experiment_ended

if [[ "$USE_LOCAL_INTROSPECTOR" = "true" ]]
then
  echo "Shutting down introspector"
  curl --silent http://localhost:8080/api/shutdown || true
fi

# Wait for the report process to finish uploading.
wait $pid_report

$PYTHON -m report.trends_report \
  --results-dir ${LOCAL_RESULTS_DIR:?} \
  --output-path "gs://oss-fuzz-gcb-experiment-run-logs/trend-reports/${GCS_TREND_REPORT_PATH:?}" \
  --name ${EXPERIMENT_NAME:?} \
  --date ${DATE:?} \
  --url "https://llm-exp.oss-fuzz.com/Result-reports/${GCS_REPORT_DIR:?}" \
  --benchmark-set ${BENCHMARK_SET:?} \
  --run-timeout ${RUN_TIMEOUT:?} \
  --num-samples ${NUM_SAMPLES:?} \
  --llm-fix-limit ${LLM_FIX_LIMIT:?} \
  --model ${MODEL:?} \
  --tags ${FREQUENCY_LABEL:?} ${SUB_DIR:?} \
  --commit-hash "$(git rev-parse HEAD)" \
  --commit-date "$(git show --no-patch --format=%cs)" \
  --git-branch "$(git branch --show)"

# Exit with the return value of `./run_all_experiments`.
exit $ret_val
