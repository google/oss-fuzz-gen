#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_tokener object
    struct json_tokener *tok = json_tokener_new();
    if (!tok) {
        return 0; // Return if json_tokener_new fails
    }

    // Consume a string from the fuzzed data to simulate JSON parsing
    std::string json_string = fuzzed_data.ConsumeRemainingBytesAsString();
    json_tokener_parse_ex(tok, json_string.c_str(), json_string.size());

    // Call the function-under-test
    enum json_tokener_error error = json_tokener_get_error(tok);

    // Clean up
    json_tokener_free(tok);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
