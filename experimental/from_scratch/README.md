# Sample tooling for generating harnesses for a codebase without harnesses


To run this you need a local version of Fuzz Introspector and a target code
base you want to analyse.

## Setting up

The first step is to create a virtual environment with Fuzz Introspector
installed and also OSS-Fuzz-gen dependencies installed. The following
commands achieve this:

```sh
# Create virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Install Fuzz Introspector in virtual environment
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/src
python3 -m pip install .
cd ../../

# Clone OSS-Fuzz-gen and install dependencies
# Clone oss-fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3 -m pip install -r ./requirements.txt
```

## Run harness generation on C code

Sample run where `${MODEL}` holds your model name:

Perform the following operations from inside the OSS-Fuzz-gen repository
at the root of the repository. In this example, we generate a target based
on the function name of the target function.

```sh
# Prepare a target
git clone https://github.com/dvhar/dateparse ../dateparse

# Generate a harness with function name
python3 -m experimental.from_scratch.generate \
  -l c++ \
  -m ${MODEL} \
  -f dateparse \
  -t ../dateparse/ \
  -o out_cpp

# Show harness
cat out_cpp/01.rawoutput
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
```

## Run harness generation on Java code
Sample run where `${MODEL}` holds your model name:

Perform the following operations from inside the OSS-Fuzz-gen repository
at the root of the repository.

In comparison to the C example above, in this example we provide souce
file and source line of the function we would to fuzz. In this case,
it's line 1200 of `JSONArray.java` which is the [put](https://github.com/stleary/JSON-java/blob/42afb3404556726a6324a2eb135124d9c39eb13d/src/main/java/org/json/JSONArray.java#L1200) function.

```sh
# Prepare a target
git clone https://github.com/stleary/JSON-java ../json-java

# Generate a harness with source file and line
python3 -m experimental.from_scratch.generate \
  -l java \
  -m ${MODEL} \
  -s JSONArray.java \
  -sl 1200 \
  -t ../json-java/ \
  -o out_java

cat out_java/01.rawoutput
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