#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" int json_parse_int64(const char *, int64_t *);

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a string from the fuzzed data
    std::string json_string = fuzzed_data.ConsumeBytesAsString(fuzzed_data.remaining_bytes());
    const char *json_cstr = json_string.c_str();

    // Prepare an int64_t variable to store the result
    int64_t result;

    // Call the function-under-test
    json_parse_int64(json_cstr, &result);

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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
