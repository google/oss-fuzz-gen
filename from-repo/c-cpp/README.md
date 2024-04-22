# Auto-build oss-fuzz projects from a GitHub repo URL


To run:

```sh
# prepare
export OPENAI_API_KEY=your-api-key
git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz-10

git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen/from-repo/c-cpp
python3 ./runner.py -o ~/tmp/oss-fuzz-10 -t 15 -i TARGET_REPO_URL
```
