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

set -x
BASE_DIR=$PWD
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector
ROOT_FI=$PWD
cd tools/web-fuzzing-introspection
${PYTHON} -m pip install -r ./requirements.txt

# Create the database for the projects we are interested in. This is done
# by parsing the benchmark directory to FI, which will interpret this and
# generate a database for the projects corresponding to the .yaml files in
# the benchmark directory.
cd app/static/assets/db/
${PYTHON} ./web_db_creator_from_summary.py \
    --output-dir=$PWD \
    --input-dir=$PWD \
    --base-offset=1 \
    --includes=$BASE_DIR/benchmark-sets/${BENCHMARK_SET}

cd $ROOT_FI/tools/web-fuzzing-introspection/app/

# Start a local webserver
cd $ROOT_FI/tools/web-fuzzing-introspection/app/
FUZZ_INTROSPECTOR_SHUTDOWN=1 $PYTHON ./main.py >> /dev/null &

# Wait until the server has launched
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
echo "Local version of introspector is up and running"

# Restore base dir as current dir
cd $BASE_DIR
