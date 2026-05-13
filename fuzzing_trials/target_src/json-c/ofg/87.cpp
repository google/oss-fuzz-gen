#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data_provider(data, size);

    // Extract a string from the fuzzed data
    std::string json_string = fuzzed_data_provider.ConsumeRandomLengthString();

    // Parse the JSON string to create a JSON object
    struct json_object *json_obj = json_tokener_parse(json_string.c_str());

    // If parsing was successful, perform operations on the JSON object
    if (json_obj != nullptr) {
        // Example operation: get a string representation of the JSON object
        const char *json_str = json_object_to_json_string(json_obj);

        // Free the allocated json object to prevent memory leaks
        json_object_put(json_obj);
    }

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
