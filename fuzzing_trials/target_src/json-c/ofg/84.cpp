#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h" // Correct path for json-c library
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

// Example serializer function
int example_serializer(struct json_object *obj, struct printbuf *pb, int level, int flags) {
    return sprintbuf(pb, "{}"); // Simple example appending an empty JSON object
}

// Example delete function
void example_delete(struct json_object *obj, void *ptr) {
    // Example delete function that does nothing
}

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    json_object *jsonObj = json_object_new_object();

    // Function pointers
    json_object_to_json_string_fn *to_json_fn = example_serializer;
    json_object_delete_fn *delete_fn = example_delete;

    // Consume some bytes for a void pointer, we will just use it as a dummy pointer
    std::string dummy_data = fuzzed_data.ConsumeRandomLengthString(size);

    // Ensure the size of the string is equal to the argument given to ConsumeRandomLengthString
    if (dummy_data.size() <= size) {
        void *userdata = const_cast<char*>(dummy_data.data());

        // Call the function-under-test
        json_object_set_serializer(jsonObj, to_json_fn, userdata, delete_fn);
    }

    // Cleanup
    json_object_put(jsonObj);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
