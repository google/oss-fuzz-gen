#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstddef>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h"

extern "C" int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    json_object *jobj = json_object_new_object();

    // Define json_object_to_json_string_fn and json_object_delete_fn function pointers
    json_object_to_json_string_fn *to_json_string_fn = nullptr;
    json_object_delete_fn *delete_fn = nullptr;

    // Use FuzzedDataProvider to decide whether to assign a dummy function to the function pointers
    if (fuzzed_data.ConsumeBool()) {
        to_json_string_fn = [](json_object *jso, struct printbuf *pb, int level, int flags) -> int {
            const char* json_str = json_object_to_json_string_ext(jso, flags);
            return printbuf_memappend(pb, json_str, strlen(json_str));
        };
    }

    if (fuzzed_data.ConsumeBool()) {
        delete_fn = [](json_object *jso, void *userdata) {
            // Dummy delete function
        };
    }

    // Create a dummy userdata pointer
    void *userdata = reinterpret_cast<void*>(fuzzed_data.ConsumeIntegral<uintptr_t>());

    // Call the function-under-test
    json_object_set_serializer(jobj, to_json_string_fn, userdata, delete_fn);

    // Cleanup
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
