BASE_OFG=$PWD
# To start, you need to specify which model you will
# be using for the experiments. You need to set the MODEL
# environment variable now.

# Create a working set up.
./scripts/run-new-oss-fuzz-project/setup.sh

# Create an OSS-Fuzz project that will be used for the experiment.
cd work/oss-fuzz/projects
git clone https://github.com/AdaLogics/oss-fuzz-auto

cd $BASE_OFG

# Now run our the generation on our newly created OSS-Fuzz project.
./scripts/run-new-oss-fuzz-project/run-project.sh oss-fuzz-auto

# Once finished, check results
python3 -m report.web -r results -s

# Navigate to localhost:8012
