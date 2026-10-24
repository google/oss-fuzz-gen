#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Check if the data size is sufficient to create a meaningful plist
    if (size == 0) {
        return 0; // No operation if data is empty
    }

    // Initialize plist_t object
    plist_t plist = plist_new_data(reinterpret_cast<const char*>(data), static_cast<uint64_t>(size));

    if (plist == nullptr) {
        return 0; // Return if plist creation failed
    }

    // Initialize the output parameters
    char *json_output = nullptr;
    uint32_t json_length = 0;
    int format = 0; // Assuming 0 is a valid format for plist_to_json

    // Call the function-under-test
    plist_err_t result = plist_to_json(plist, &json_output, &json_length, format);

    // Check the result of plist_to_json to ensure it processed the input
    if (result == PLIST_ERR_SUCCESS && json_output != nullptr) {
        // Optionally process json_output or check json_length for further validation
    }

    // Clean up
    if (json_output != nullptr) {
        free(json_output);
    }
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
