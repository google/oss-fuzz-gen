extern "C" {
#include <plist/plist.h>
}

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Create a plist object from the input data
    plist_t plist = NULL;
    if (size > 0) {
        plist_from_bin((const char*)data, size, &plist);
    }

    // Ensure plist is not NULL
    if (plist != NULL) {
        // Call the function-under-test
        uint32_t array_size = plist_array_get_size(plist);

        // Optionally use the result to prevent any compiler optimizations
        if (array_size > 0) {
            // Do something with array_size, e.g., print or log, if necessary
        }

        // Free the plist object
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

    LLVMFuzzerTestOneInput_171(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
