#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string>

// Include the correct headers for json-c functions
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider with the input data.
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the data to create a JSON string.
    std::string json_str = fuzzed_data.ConsumeRandomLengthString(1024);

    // Parse the JSON string to create a json_object.
    struct json_object *src_json_obj = json_tokener_parse(json_str.c_str());

    // Ensure that the source json_object is not NULL.
    if (src_json_obj == nullptr) {
        return 0; // If parsing fails, exit early.
    }

    // Prepare the destination json_object pointer.
    struct json_object *dest_json_obj = nullptr;

    // Define a shallow copy function pointer (can be NULL for default behavior).
    json_c_shallow_copy_fn *shallow_copy_fn = nullptr;

    // Call the function-under-test.
    json_object_deep_copy(src_json_obj, &dest_json_obj, shallow_copy_fn);

    // Clean up the allocated json_objects.
    json_object_put(src_json_obj);
    if (dest_json_obj != nullptr) {
        json_object_put(dest_json_obj);
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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
