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

BENCHMARK_SET=$1

# Create (small) DB.
(cd /fi/tools/web-fuzzing-introspection/app/static/assets/db/ && \
    find "/experiment/benchmark-sets/$BENCHMARK_SET" -type f -name "*.yaml" \
    -exec basename {} .yaml \; | sort > must_include_small.config && \
    ./launch_minor_oss_fuzz.sh)

# Start the web app.
(cd /fi/tools/web-fuzzing-introspection/app/ && \
    python3 ./main.py)
