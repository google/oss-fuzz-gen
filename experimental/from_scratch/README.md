# Sample tooling for generating harnesses for a codebase without harnesses


To run this you need a local version of Fuzz Introspector and a target code
base you want to analyse.

Sample run where `${MODEL}` holds your model name:

```sh
# Create virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Install Fuzz Introspector in virtual environment
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/src
python3 -m pip install -e .
cd ../../

# Prepare a target
## C++
git clone https://github.com/dvhar/dateparse
## Java
git clone https://github.com/stleary/JSON-java json-java

# Clone oss-fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3 -m pip install -r ./requirements.txt

# Generate a harness (C++) (with function name)
python3 -m experimental.from_scratch.generate \
  -e c++ \
  -l ${MODEL} \
  -f dateparse \
  -t ../dateparse/ \
  -r responses_cpp

# Generate a harness (Java) (with source file and line)
python3 -m experimental.from_scratch.generate \
  -e java \
  -l ${MODEL} \
  -s JSONArray.java \
  -sl 1200 \
  -t ../json-java/ \
  -r responses_java

# Show harness
cat responses_cpp/01.rawoutput
"""
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
"""

cat responses_java/01.rawoutput
"""
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.json.JSONArray;

public class JSONArray {
    public static void fuzzerInitialize() {
        // Initializing objects for fuzzing
    }

    public static void fuzzerTearDown() {
        // Tear down objects after fuzzing
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        boolean bool = data.consumeBoolean();

        JSONArray jsonArray = new JSONArray();
        try {
            jsonArray.put(bool);
        } catch (RuntimeException e) {
            // Catch potential RuntimeException
        } finally {
            try {
                jsonArray.close();
            } catch (Exception ignored) {
                // Ignoring any exception in closing the resource
            }
        }
    }
}
"""
```

