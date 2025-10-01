#!/bin/bash

OSS_FUZZ_GEN_DIR=$PWD
OSS_FUZZ_GEN_MODEL=${MODEL}
OSS_FUZZ_DIR=$OSS_FUZZ_GEN_DIR/work/oss-fuzz
FI_DIR=$OSS_FUZZ_GEN_DIR/work/fuzz-introspector
BENCHMARK_HEURISTICS=far-reach-low-coverage,low-cov-with-fuzz-keyword,easy-params-far-reach
VAR_HARNESSES_PER_PROJECT=4
PROJECTS=${@}

comma_separated=""
for proj in ${PROJECTS}; do
  echo ${proj}
  comma_separated="${comma_separated}${proj},"
done
comma_separated=${comma_separated::-1}

# Specify LogicFuzz to not clean up the OSS-Fuzz project. Enabling
# this will cause all changes in the OSS-Fuzz repository to be nullified.
export OFG_CLEAN_UP_OSS_FUZZ=0

echo "Targeting project: $project"

# Generate fresh introspector reports that OFG can use as seed for auto
# generation.
echo "Creating introspector reports"
cd ${OSS_FUZZ_DIR}

for p2 in ${PROJECTS}; do
  python3 $FI_DIR/oss_fuzz_integration/runner.py \
    introspector $p2 1 --disable-webserver
  # Reset is necessary because some project exeuction
  # could break the display encoding which affect
  # the later LogicFuzz execution.
  reset
done

# Shut down the existing webapp if it's running
curl --silent http://localhost:8080/api/shutdown || true

# Create Fuzz Introspector's webserver DB
echo "[+] Creating the webapp DB"
cd $FI_DIR/tools/web-fuzzing-introspection/app/static/assets/db/
python3 ./web_db_creator_from_summary.py \
    --local-oss-fuzz ${OSS_FUZZ_DIR}

# Start webserver
echo "Shutting down server in case it's running"
curl --silent http://localhost:8080/api/shutdown || true

echo "[+] Launching FI webapp"
cd $FI_DIR/tools/web-fuzzing-introspection/app/
FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=${OSS_FUZZ_DIR} \
  python3 ./main.py >> /dev/null &

# Wait for the webapp to start.
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

# Run LogicFuzz on the projects
echo "[+] Running LogicFuzz experiment"
cd ${OSS_FUZZ_GEN_DIR}

# Hack to ensure no complaints from oss_fuzz_checkout.py
mkdir -p ${OSS_FUZZ_DIR}/venv

# Run LogicFuzz
# - Generate benchmarks
# - Use a local version version of OSS-Fuzz (the one in /work/oss-fuzz)
EXTRA_ARGS="${EXTRA_OFG_ARGS}"
LLM_NUM_EVA=4 LLM_NUM_EXP=4 ./run_all_experiments.py \
    --model=$OSS_FUZZ_GEN_MODEL \
    -g ${BENCHMARK_HEURISTICS} \
    -gp ${comma_separated} \
    -gm ${VAR_HARNESSES_PER_PROJECT} \
    -of ${OSS_FUZZ_DIR} \
    -e http://127.0.0.1:8080/api ${EXTRA_ARGS}

echo "Shutting down started webserver"
curl --silent http://localhost:8080/api/shutdown || true
