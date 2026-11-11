#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h" // Correct path for json_object functions
#include "/src/json-c/json_tokener.h" // Correct path for json_tokener functions
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    FuzzedDataProvider fuzzed_data(data, size);

    // Use ConsumeRandomLengthString to create a JSON string
    std::string json_string = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes());

    // Parse the JSON string into a json_object
    struct json_object *jobj = json_tokener_parse(json_string.c_str());

    // Ensure the json_object is not NULL before calling the function
    if (jobj != NULL) {
        // Call the function-under-test
        json_bool result = json_object_get_boolean(jobj);

        // Clean up the json_object
        json_object_put(jobj);
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
