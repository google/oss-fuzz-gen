#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_object.h"

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    if (size < sizeof(struct json_tokener)) {
        return 0;
    }

    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_tokener object using fuzzed data
    struct json_tokener* tokener = json_tokener_new();
    if (tokener == nullptr) {
        return 0;
    }

    // Fuzz the json_tokener object by consuming some bytes
    std::string json_string = fuzzed_data.ConsumeRandomLengthString(size);

    // Parse the JSON string to manipulate the tokener
    json_object* jobj = json_tokener_parse_ex(tokener, json_string.c_str(), json_string.size());

    // Free the json_object if it was created
    if (jobj != nullptr) {
        json_object_put(jobj);
    }

    // Call the function-under-test
    json_tokener_free(tokener);

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
