#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Consume a double value from the fuzzed data
    double double_value = stream.ConsumeFloatingPoint<double>();

    // Consume a string from the fuzzed data
    std::string str = stream.ConsumeRemainingBytesAsString();

    // Call the function-under-test
    struct json_object *obj = json_object_new_double_s(double_value, str.c_str());

    // Clean up the json_object to prevent memory leaks
    if (obj != nullptr) {
        json_object_put(obj);
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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
