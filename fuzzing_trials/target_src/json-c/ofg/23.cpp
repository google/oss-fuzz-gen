#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstring>

extern "C" int json_parse_uint64(const char *, uint64_t *);

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume bytes as a string for the first parameter
    std::string json_string = fuzzed_data.ConsumeBytesAsString(size);

    // Ensure the string is null-terminated
    const char *json_cstr = json_string.c_str();

    // Prepare a uint64_t variable for the second parameter
    uint64_t result = 0;

    // Call the function-under-test
    json_parse_uint64(json_cstr, &result);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
