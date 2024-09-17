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



if [ -d "work" ]
then
  echo "\"work\" directory is already set up."
  echo "Please remove this directory if you would like to rerun the setup."
  exit 0
fi

mkdir work
cd work
WORK=$PWD

echo "[+] Setting up Fuzz Introspector"
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/tools/web-fuzzing-introspection
python3 -m pip install -r ./requirements.txt
cd $WORK

echo "[+] Making a local OSS-Fuzz folder we can reuse"
git clone https://github.com/google/oss-fuzz


echo "[+] Done"
echo "You can now use $WORK/ as your base folder for experiments."