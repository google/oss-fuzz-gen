#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the fuzzing data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string from the fuzzed data
    std::string str = fuzzed_data.ConsumeRandomLengthString();

    // Consume an integer for the string length
    int str_len = fuzzed_data.ConsumeIntegralInRange<int>(0, str.size());

    // Call the function-under-test
    struct json_object *json_obj = json_object_new_string_len(str.c_str(), str_len);

    // Clean up the created json_object
    if (json_obj != nullptr) {
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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
