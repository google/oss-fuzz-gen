#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    json_object *jobj = json_object_new_object();
    if (jobj == nullptr) return 0;

    // Extract a random length string from the fuzzed data
    std::string str = fuzzed_data.ConsumeRandomLengthString(size);

    // Extract an integer from the fuzzed data
    int len = fuzzed_data.ConsumeIntegralInRange<int>(0, static_cast<int>(str.size()));

    // Call the function under test
    json_object_set_string_len(jobj, str.c_str(), len);

    // Decrement the reference count of the json_object to free it
    json_object_put(jobj);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
