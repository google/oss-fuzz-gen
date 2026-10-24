#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Initialize plist_t and uint64_t pointer
    plist_t plist = NULL;
    uint64_t *length = (uint64_t*)malloc(sizeof(uint64_t));
    if (length == NULL) {
        return 0; // Exit if memory allocation fails
    }
    *length = 0; // Initialize length

    // Create a plist from the input data
    plist_from_bin((const char*)data, size, &plist);

    // Call the function-under-test
    const char *result = plist_get_string_ptr(plist, length);

    // Clean up
    if (plist != NULL) {
        plist_free(plist);
    }
    free(length);

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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
