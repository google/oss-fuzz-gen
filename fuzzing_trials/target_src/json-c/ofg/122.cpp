#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h" // Correct path for json-c library
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    json_object *jobj = json_object_new_object();
    if (jobj == nullptr) {
        return 0; // If memory allocation fails, return early
    }

    // Consume a key name from the fuzzed data
    std::string key = fuzzed_data.ConsumeRandomLengthString();

    // Consume a boolean value from the fuzzed data
    json_bool jbool = fuzzed_data.ConsumeBool();

    // Set the boolean value in the json object with the key
    json_object_object_add(jobj, key.c_str(), json_object_new_boolean(jbool));

    // Free the json_object to prevent memory leaks
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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
