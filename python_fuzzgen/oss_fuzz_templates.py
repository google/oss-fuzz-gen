DOCKERFILE_PYTHON_INTROSPECTOR = """FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get install -y python3.9 python3.9-dev && \\
    ln --force -s /usr/bin/python3.9 /usr/local/bin/python3 && \\
    apt-get install -y python3-pip && \\
    python3 -m pip install cython virtualenv
RUN python3 -m pip install --upgrade pip setuptools meson ninja numpy pybind11 cython pythran setuptools_scm
RUN git clone https://github.com/ossf/fuzz-introspector $SRC/fuzz-introspector && \\
    cd fuzz-introspector && \\
    git submodule init && \\
    git submodule update && \\
    python3 -m pip install -r ./requirements.txt && \\
    python3 -m pip install frontends/python/PyCG

#RUN python3 -m pip install -r /fuzz-introspector/requirements.txt
#RUN python3 -m pip install /fuzz-introspector/frontends/python/PyCG

RUN git clone TARGET_REPO $SRC/proj
COPY *.sh *.py $SRC/
WORKDIR $SRC/fuzz-introspector/frontends/python
"""


BUILD_PYTHON_INTROSPECTOR="""python3 main.py --fuzzer $SRC/fuzz_1.py --package=$SRC/proj
cp ./fuzzerLogFile-fuzz_1.data.yaml $OUT/
"""

BUILD_PYTHON_HARNESSES="""cd $SRC/proj

python3 -m pip install .

mkdir -p $SRC/fuzzer-builds
cd $SRC/fuzzer-builds
cp $SRC/fuzz_*.py .

for fuzzer in $(find . -name 'fuzz_*.py'); do
  # Compile the fuzzer but do not care if the build fails.
  compile_python_fuzzer $fuzzer || true
done
"""


PROJECT_YAML_PYTHON_INTROSPETOR="""homepage: https://google.com
main_repo: TARGET_REPO
language: python
fuzzing_engines:
- libfuzzer
sanitizers:
- address
- undefined
primary_contacts: oss-fuzz-gen@google.com"""


FUZZ_TEMPLATE_PYTHON="""import sys
import atheris


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
"""
