#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data_provider(data, size);

    // Consume a random length string from the fuzzed data to create a JSON object
    std::string json_string = fuzzed_data_provider.ConsumeRandomLengthString(
        fuzzed_data_provider.remaining_bytes());

    // Create a JSON object from the string
    json_object *jobj = json_tokener_parse(json_string.c_str());

    // Check if the JSON object was created successfully
    if (jobj != nullptr) {
        // Call the function-under-test
        void *userdata = json_object_get_userdata(jobj);

        // Clean up the JSON object
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
