#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Initialize a plist_t variable
    plist_t plist = nullptr;

    // Create a plist from the input data
    if (size > 0) {
        plist_from_bin((const char*)data, size, &plist);
    }

    // Ensure plist is not NULL before calling the function
    if (plist != nullptr) {
        // Call the function-under-test
        uint32_t dict_size = plist_dict_get_size(plist);

        // Optionally, perform some operations with dict_size
        // (e.g., print it, use it in some logic, etc.)
        // For this harness, we just call the function to ensure it executes.
    }

    // Free the plist to avoid memory leaks
    if (plist != nullptr) {
        plist_free(plist);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
