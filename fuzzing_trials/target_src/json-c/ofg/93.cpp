#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a json_object
    json_object *jobj = json_object_new_object();
    if (jobj == nullptr) {
        return 0; // If creation fails, exit early
    }

    // Consume some bytes to use as user data
    size_t user_data_size = fuzzed_data.ConsumeIntegralInRange<size_t>(1, 1024);
    std::vector<uint8_t> user_data = fuzzed_data.ConsumeBytes<uint8_t>(user_data_size);
    
    // Validate that the size of the vector matches the requested size
    if (user_data.size() != user_data_size) {
        json_object_put(jobj);
        return 0; // Exit early if the size does not match
    }

    void *user_data_ptr = user_data.data();

    // Define a simple delete function
    auto delete_fn = [](json_object *jobj, void *userdata) {
        // Custom delete logic can be added here
        (void)jobj; // Suppress unused variable warning
        (void)userdata; // Suppress unused variable warning
    };

    // Call the function-under-test
    json_object_set_userdata(jobj, user_data_ptr, delete_fn);

    // Clean up
    json_object_put(jobj); // Decrement the reference count of the json_object

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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
