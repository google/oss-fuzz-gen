#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Initialize plist_t
    plist_t plist = NULL;
    char *string_val = NULL;

    // Create a plist from the input data
    plist_from_bin((const char*)data, size, &plist);

    // Ensure plist is not NULL
    if (plist != NULL) {
        // Call the function-under-test
        plist_get_string_val(plist, &string_val);

        // Free the string if it was allocated
        if (string_val != NULL) {
            free(string_val);
        }

        // Free the plist
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
