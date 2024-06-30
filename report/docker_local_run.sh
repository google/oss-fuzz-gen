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

# Comma separated project list
PROJECTS=${TARGET_PROJECTS}
BENCHMARK_HEURISTICS=far-reach-low-coverage
ROOT_FI=/tmp/fuzz-introspector
OSS_FUZZ_GEN_MODEL=${LLM_MODEL}

BASE_DIR=$PWD

# Clean and set up Fuzz Introspector
ROOT_FI=$(mktemp -d)
echo "Using Fuzz Introspector dir: ${ROOT_FI}"
echo $WORK_DIR
git clone https://github.com/ossf/fuzz-introspector $ROOT_FI
cd $ROOT_FI
python3 -m pip install -r ./requirements.txt


# Create a local DB
cd tools/web-fuzzing-introspection/app/static/assets/db/
python3 ./web_db_creator_from_summary.py \
  --includes="${PROJECTS}"

# Start webserver DB
echo "Shutting down server in case it's running"
curl --silent http://localhost:8080/api/shutdown || true

echo "[+] Launching FI webapp"
cd $ROOT_FI/tools/web-fuzzing-introspection/app/
FUZZ_INTROSPECTOR_SHUTDOWN=1 python3 ./main.py >> /dev/null &

SECONDS=5
while true
do
  # Checking if exists
  MSG=$(curl -v --silent 127.0.0.1:8080 2>&1 | grep "Fuzzing" | wc -l)
  if [[ $MSG > 0 ]]; then
    echo "Found it"
    break
  fi
  echo "- Waiting for webapp to load. Sleeping ${SECONDS} seconds."
  sleep ${SECONDS}
done

# Run the experiment
echo "Running the experiment"
cd $BASE_DIR
./run_all_experiments.py \
    --model=$OSS_FUZZ_GEN_MODEL \
    -g ${BENCHMARK_HEURISTICS} \
    -gp ${PROJECTS} \
    -gm 6 \
    -e http://127.0.0.1:8080/api

echo "Shutting down started webserver"
curl --silent http://localhost:8080/api/shutdown || true
