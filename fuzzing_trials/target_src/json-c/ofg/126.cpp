#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"  // Include the header for json_tokener_parse

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Generate a string from the fuzzed data
    std::string input_string = fuzzed_data.ConsumeRandomLengthString();

    // Parse the string into a JSON object
    struct json_object *obj = json_tokener_parse(input_string.c_str());

    // Cleanup
    json_object_put(obj);

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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
