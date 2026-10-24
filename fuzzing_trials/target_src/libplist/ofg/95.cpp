#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    int plist_uint_val_compare(plist_t plist, uint64_t value);
}

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    plist_t plist = NULL;
    uint64_t test_value = 0;

    // Ensure size is sufficient to create a valid plist and extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Create a plist from the input data
    plist_from_bin((const char*)data, size, &plist);

    // Extract a uint64_t value from the data
    test_value = *((uint64_t*)data);

    // Call the function-under-test
    plist_uint_val_compare(plist, test_value);

    // Free the plist
    if (plist != NULL) {
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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
