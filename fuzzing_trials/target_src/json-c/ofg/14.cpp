#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data_provider(data, size);

    // Consume an integer for the json_tokener_new_ex function parameter
    int depth = fuzzed_data_provider.ConsumeIntegral<int>();

    // Call the function-under-test
    struct json_tokener *tokener = json_tokener_new_ex(depth);

    // Clean up
    if (tokener != nullptr) {
        json_tokener_free(tokener);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
