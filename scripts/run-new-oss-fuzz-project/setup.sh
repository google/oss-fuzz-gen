#!/bin/bash

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
