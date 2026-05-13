extern "C" {
#include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Create a plist from the input data
    plist_t original_plist = NULL;
    if (size > 0) {
        plist_from_bin((const char*)data, size, &original_plist);
    }

    // Ensure the plist is not NULL before copying
    if (original_plist != NULL) {
        // Call the function-under-test
        plist_t copied_plist = plist_copy(original_plist);

        // Free the copied plist
        plist_free(copied_plist);
    }

    // Free the original plist
    plist_free(original_plist);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
