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

UPDATE_INDEX_TOPIC=llm-trends-report
# gcs notification
UPDATE_INDEX_BUCKET='gs://oss-fuzz-gcb-experiment-run-logs'
UPDATE_INDEX_PREFIX='trend-reports/'
# function
UPDATE_INDEX_FUNCTION=llm-trends-report-index
UPDATE_INDEX_FILENAME=update_index.py
UPDATE_INDEX_ENTRY_POINT=trends_report_index

UPDATE_WEB_TOPIC=llm-trends-report-web
# function
UPDATE_WEB_FUNCTION=llm-trends-report-web
UPDATE_WEB_FILENAME=update_web.py
UPDATE_WEB_ENTRY_POINT=trends_report_web
# scheduler
UPDATE_WEB_SCHEDULER=llm-trends-report-web
UPDATE_WEB_CRON='0 * * * *'
UPDATE_WEB_MESSAGE='update'

function deploy_pubsub_topic {
  topic=$1
  project=$2

  echo "gcloud pubsub topics describe $topic --project $project"
  if ! gcloud pubsub topics describe $topic --project $project;
    then
      gcloud pubsub topics create $topic --project $project
  fi
}

function deploy_scheduler {
  scheduler_name=$1
  schedule="$2"
  topic=$3
  message="$4"
  project=$5

  if gcloud scheduler jobs describe $scheduler_name --project $project ;
    then
      gcloud scheduler jobs update pubsub $scheduler_name \
        --project $project \
        --schedule "$schedule" \
        --topic $topic \
        --message-body "$message"
    else
      gcloud scheduler jobs create pubsub $scheduler_name \
        --project $project \
        --schedule "$schedule" \
        --topic $topic \
        --message-body "$message"
  fi
}

function deploy_cloud_function {
  name=$1
  filename=$2
  entry_point=$3
  topic=$4
  project=$5

  gcloud functions deploy $name \
    --entry-point $entry_point \
    --trigger-topic $topic \
    --runtime python312 \
    --project $project \
    --timeout 540 \
    --region us-central1 \
    --max-instances 1 \
    --memory 4096MB \
    --set-build-env-vars=GOOGLE_FUNCTION_SOURCE=$filename
}

if [ $# == 1 ]; then
  PROJECT_ID=$1
else
  echo -e "\n Usage ./deploy_functions.sh <project-name>"; exit;
fi

deploy_pubsub_topic $UPDATE_INDEX_TOPIC $PROJECT_ID

gcloud storage buckets notifications create \
  $UPDATE_INDEX_BUCKET \
  --topic=$UPDATE_INDEX_TOPIC \
  --event-types=OBJECT_FINALIZE \
  --object-prefix="$UPDATE_INDEX_PREFIX"

deploy_cloud_function $UPDATE_INDEX_FUNCTION \
  $UPDATE_INDEX_FILENAME \
  $UPDATE_INDEX_ENTRY_POINT \
  $UPDATE_INDEX_TOPIC \
  $PROJECT_ID

deploy_pubsub_topic $UPDATE_WEB_TOPIC $PROJECT_ID

deploy_scheduler $UPDATE_WEB_SCHEDULER \
  "$UPDATE_WEB_CRON" \
  $UPDATE_WEB_TOPIC \
  "$UPDATE_WEB_MESSAGE" \
  $PROJECT_ID

deploy_cloud_function $UPDATE_WEB_FUNCTION \
  $UPDATE_WEB_FILENAME \
  $UPDATE_WEB_ENTRY_POINT \
  $UPDATE_WEB_TOPIC \
  $PROJECT_ID
