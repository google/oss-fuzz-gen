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
##   additional_args are passed through to report.web (e.g., --with-csv)

# TODO(dongge): Re-write this script in Python as it gets more complex.

RESULTS_DIR=$1
GCS_DIR=$2
BENCHMARK_SET=$3
MODEL=$4
# All remaining arguments are additional args for report.web
shift 4
REPORT_ADDITIONAL_ARGS="$@"
DATE=$(date '+%Y-%m-%d')

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

# Give the experiment a short head start while still publishing early
# diagnostics. The interval can be overridden for local pipeline tests.
sleep "${REPORT_INITIAL_DELAY:-30}"

echo "Report results directory: ${RESULTS_DIR}"
echo "Report GCS directory: ${GCS_DIR}"
mkdir -p results-report

update_report() {
  echo "Inspecting result files before report generation."
  if [[ -d "${RESULTS_DIR}" ]]; then
    find "${RESULTS_DIR}" -maxdepth 5 -type f | sort | head -200
  else
    echo "Result directory does not exist: ${RESULTS_DIR}"
  fi

  # Do not leave files from an earlier report generation in the upload set.
  rm -rf results-report
  mkdir -p results-report

  # Generate the report
  echo "Generating report."
  if [[ $GCS_DIR != '' ]]; then
    CLOUD_BASE_URL="https://llm-exp.oss-fuzz.com/Result-reports/${GCS_DIR}"
    $PYTHON -m report.web -r "${RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report --base-url "$CLOUD_BASE_URL" --gcs-dir "${GCS_DIR}" $REPORT_ADDITIONAL_ARGS
  else
    $PYTHON -m report.web -r "${RESULTS_DIR:?}" -b "${BENCHMARK_SET:?}" -m "$MODEL" -o results-report $REPORT_ADDITIONAL_ARGS
  fi

  report_status=$?
  if [[ $report_status -ne 0 ]]; then
    echo "Report generation failed with exit code ${report_status}."
  elif [[ ! -f results-report/index.html ]]; then
    echo "Report generation did not create results-report/index.html."
    report_status=1
  else
    cd results-report || return 1

    # Upload the report to GCS.
    echo "Uploading the report."
    BUCKET_PATH="gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"
    # Upload HTMLs.
    if ! gcloud storage cp --recursive --content-type="text/html" \
           --cache-control="public, max-age=3600" \
           . "$BUCKET_PATH"; then
      echo "HTML report upload failed."
      report_status=1
    fi
    # Find all JSON files and upload them, removing the leading './'
    while read -r file; do
      file_path="${file#./}"  # Remove the leading "./".
      if ! gcloud storage cp --content-type="application/json" \
          --cache-control="public, max-age=3600" "$file" "$BUCKET_PATH/$file_path"; then
        echo "JSON report upload failed for ${file_path}."
        report_status=1
      fi
    done < <(find . -name '*json')

    cd .. || return 1
  fi

  # Upload raw results after publishing the report. A partial or empty
  # results directory must not prevent the HTML report from being published.
  if [[ -d "${RESULTS_DIR}" ]]; then
    echo "Uploading raw results."
    if ! gcloud storage cp --recursive "${RESULTS_DIR:?}" \
        "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"; then
      echo "Raw results upload failed; keeping the published report."
    fi
  else
    echo "Raw results directory is not available yet."
  fi

  if [[ $report_status -ne 0 ]]; then
    return "$report_status"
  fi

  echo "See the published report at https://llm-exp.oss-fuzz.com/Result-reports/${GCS_DIR:?}/"

  # Upload training data.
  echo "Uploading training data."
  rm -rf 'training_data'
  gcloud storage rm --recursive "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}/training_data" || true

  # $PYTHON -m data_prep.parse_training_data \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --group \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --coverage \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #$PYTHON -m data_prep.parse_training_data --coverage --group \
  #  --experiment-dir "${RESULTS_DIR:?}" --save-dir 'training_data'
  #gsutil -q cp -r 'training_data' \
  #  "gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/${GCS_DIR:?}"
}

while [[ ! -f /experiment_ended ]]; do
  update_report
  update_status=$?
  if [[ $update_status -ne 0 ]]; then
    echo "Report update failed with exit code ${update_status}; retrying."
  fi
  echo "Experiment is running..."
  sleep 600
done

echo "Experiment finished."
update_report
echo "Final report uploaded."
