#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"  // Include the correct header for json_tokener_error

// Define the maximum value for the json_tokener_error enumeration
constexpr json_tokener_error JSON_TOKENER_ERROR_MAX = json_tokener_error_memory;

extern "C" int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume an integral value to represent the enumeration type
    auto error_type = static_cast<json_tokener_error>(
        fuzzed_data.ConsumeIntegralInRange<int>(json_tokener_success, JSON_TOKENER_ERROR_MAX));

    // Call the function-under-test
    const char *description = json_tokener_error_desc(error_type);

    // Use the result to prevent compiler optimizations (e.g., prevent unused variable warning)
    if (description) {
        (void)description;
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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
