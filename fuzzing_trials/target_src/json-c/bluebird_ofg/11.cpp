#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstdint>
#include <cstdlib>
#include <string>

// Include the correct header for json-c functions
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string from the input data for json_object creation
    std::string json_string = fuzzed_data.ConsumeRandomLengthString();
    
    // Parse the JSON string to create a json_object
    struct json_object *jobj = json_tokener_parse(json_string.c_str());

    // If parsing failed, return early
    if (jobj == nullptr) {
        return 0;
    }

    // Consume an int64_t value from the input data
    int64_t increment_value = fuzzed_data.ConsumeIntegral<int64_t>();

    // Call the function-under-test
    json_object_int_inc(jobj, increment_value);

    // Decrement the reference count of the json_object
    json_object_put(jobj);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
