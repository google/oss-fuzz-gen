# Sample tooling for generating harnesses for a codebase without harnesses


To run this you need a local version of Fuzz Introspector and a target code
base you want to analyse.

Sample run where `${MODEL}` holds your model name:

``sh
# Create virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Install Fuzz Introspector in virtual environment
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/src
python3 -m pip install -e .
cd ../../


# Prepare a target
git clone https://github.com/dvhar/dateparse

# Clone oss-fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen

# Generate a tool
python3 -m experimental.from_scratch.generate \
  -l ${MODEL} \
  -f dateparse \
  -t ../dateparse/

# Show harness
cat responses/01.rawoutput
#include <stdio.h>
#include <string.h>

typedef struct{int year;int month; int day;} date_t;

int dateparse(const char* datestr, date_t* t, int *offset, int stringlen); // prototype

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    date_t t;
    int offset = 0;
    
    // ensure NULL termination for the data string
    char* datestr = (char*)malloc(size + 1);
    if (!datestr)
        return 0;
    memcpy(datestr, data, size);
    datestr[size] = '\0';
    
    dateparse(datestr, &t, &offset, size);

    free(datestr);
    return 0;
}
```