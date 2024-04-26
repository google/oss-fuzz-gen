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
##   bash report/upload_report.sh results_dir [gcs_dir]
##
##   results_dir is the local directory with the experiment results.
##   gcs_dir is the name of the directory for the report in gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/.
##     Defaults to '$(whoami)-%YY-%MM-%DD'.

# TODO(dongge): Re-write this script in Python as it gets more complex.

RESULTS_DIR=$1
GCS_DIR=$2
BENCHMARK_SET=$3
MODEL=$4
WEB_PORT=8080
DATE=$(date '+%Y-%m-%d')

# Sleep 5 minutes for the experiment to start.
sleep 300

if [[ $RESULTS_DIR = '' ]]
then
  echo 'This script takes the results directory as the first argument'
  exit 1
fi

if [[ $GCS_DIR = '' ]]
then
  echo "This script needs to take gcloud Bucket directory as the second argument. Consider using $(whoami)-${DATE:?}."
  exit 1
fi

# The LLM used to generate and fix fuzz targets.
if [[ $MODEL = '' ]]
then
  echo "This script needs to take LLM as the third argument."
  exit 1
fi

mkdir results-report

while true; do
  # Spin up the web server generating the report (and bg the process).
  $PYTHON -m report.web "${RESULTS_DIR:?}" "${WEB_PORT:?}" "${BENCHMARK_SET:?}" "$MODEL" &
  pid_web=$!

  cd results-report || exit 1

  # Recursively get all the experiment results.
  echo "Download results from localhost."
  wget2 --quiet --inet4-only --no-host-directories --http2-request-window 10 --recursive localhost:${WEB_PORT:?}/ 2>&1

  # Also fetch index JSON.
  wget2 --quiet --inet4-only localhost:${WEB_PORT:?}/json -O json 2>&1

  # Stop the server.
  kill -9 "$pid_web"

  # Upload the report to GCS.
  echo "Uploading the report."
  BUCKET_PATH="gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"
  # Upload HTMLs.
  gsutil -q -m -h "Content-Type:text/html" \
         -h "Cache-Control:public, max-age=3600" \
         cp -r . "$BUCKET_PATH"
  # Find all JSON files and upload them, removing the leading './'
  find . -name '*.json' | while read -r file; do
    file_path="${file#./}"  # Remove the leading "./".
    gsutil -q -m -h "Content-Type:application/json" \
        -h "Cache-Control:public, max-age=3600" cp "$file" "$BUCKET_PATH/$file_path"
  done

  cd ..

  # Upload the raw results into the same GCS directory.
  echo "Uploading the raw results."
  gsutil -q -m cp -r "${RESULTS_DIR:?}" \
         "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"

  echo "See the published report at https://llm-exp.oss-fuzz.com/Result-reports/${GCS_DIR:?}/"

  # Upload training data.
  echo "Uploading training data."
  rm -rf 'training_data'
  gsutil -q rm -r "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}/training_data" || true

  $PYTHON -m data_prep.parse_training_data \
    --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  $PYTHON -m data_prep.parse_training_data --group \
    --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  $PYTHON -m data_prep.parse_training_data --coverage \
    --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  $PYTHON -m data_prep.parse_training_data --coverage --group \
    --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  gsutil -q cp -r 'training_data' \
    "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"

  if [[ -f /experiment_ended ]]; then
    echo "Experiment finished."
    exit
  fi

  echo "Experiment is running..."
  sleep 600
done
