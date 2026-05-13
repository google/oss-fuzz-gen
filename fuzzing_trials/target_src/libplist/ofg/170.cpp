#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Initialize plist from data
    plist_t plist = NULL;
    if (size > 0) {
        plist_format_t format;
        plist_from_memory((const char*)data, size, &plist, &format);
    }

    // Ensure plist is not NULL before calling the function
    if (plist != NULL) {
        // Call the function-under-test
        uint32_t array_size = plist_array_get_size(plist);

        // Optionally, you can use array_size for further testing or logging
        // For example, printing it (not necessary for fuzzing)
        // printf("Array size: %u\n", array_size);

        // Free the plist object after use
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

    LLVMFuzzerTestOneInput_170(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
