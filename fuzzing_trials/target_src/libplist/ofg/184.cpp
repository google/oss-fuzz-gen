extern "C" {
    #include <plist/plist.h>
}

#include <cstring> // Include the necessary header for memcpy

extern "C" int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    // Ensure that the size is at least the size of an int64_t
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Initialize a plist_t object
    plist_t plist = plist_new_dict();

    // Extract an int64_t value from the input data
    int64_t value;
    memcpy(&value, data, sizeof(int64_t));

    // Call the function-under-test
    int result = plist_int_val_compare(plist, value);

    // Clean up the plist object
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

    LLVMFuzzerTestOneInput_184(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
