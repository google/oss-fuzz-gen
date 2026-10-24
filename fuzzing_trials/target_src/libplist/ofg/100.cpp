#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    plist_t plist_copy(plist_t);
}

extern "C" int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a plist
    if (size < 1) {
        return 0;
    }

    // Create a plist from the input data
    plist_t original_plist = plist_new_data((const char*)data, (uint32_t)size);

    // Check if plist creation was successful
    if (original_plist == NULL) {
        return 0;
    }

    // Call the function-under-test
    plist_t copied_plist = plist_copy(original_plist);

    // Free the original plist
    plist_free(original_plist);

    // Free the copied plist if it was successfully created
    if (copied_plist != NULL) {
        plist_free(copied_plist);
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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
