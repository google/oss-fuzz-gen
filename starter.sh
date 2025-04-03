#!/bin/bash
set -x
cd /
BASE=$PWD
DATA_DIR="data-dir"

PROJECTS_TO_ANALYSE=""
for d in $DATA_DIR/oss-fuzz/projects/*; do
  PROJECTS_TO_ANALYSE="${PROJECTS_TO_ANALYSE}$(basename $d),"
done

echo "${PROJECTS_TO_ANALYSE}"

# Create a minor clone of OSS-Fuzz where we will populate it with data
# for Fuzz Introspector webapp
git clone --depth=1 https://github.com/google/oss-fuzz

cd oss-fuzz
rsync -avu "$BASE/$DATA_DIR/oss-fuzz/" .

############ Start a Fuzz Introspector server
cd $BASE
git clone --depth=1 https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/tools/web-fuzzing-introspection
${PYTHON} -m pip install -r requirements.txt
#python3 -m virtualenv .venv
#.venv/bin/python3 -m pip install -r requirements.txt

# Copy the database we have created already
cd app/static/assets
rm -rf ./db
cp -rf $BASE/$DATA_DIR/fuzz_introspector_db db
cd ../../
# Launch the server
FUZZ_INTROSPECTOR_SHUTDOWN=1 FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=$BASE/$DATA_DIR/oss-fuzz ${PYTHON} main.py >>/dev/null &

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
