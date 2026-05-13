#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Initialize plist
    plist_t plist = NULL;
    plist_from_bin((const char*)data, size, &plist);

    if (plist == NULL) {
        return 0;
    }

    // Initialize variables for plist_get_data_val
    char *data_val = NULL;
    uint64_t length = 0;

    // Call the function-under-test
    plist_get_data_val(plist, &data_val, &length);

    // Free allocated memory
    if (data_val != NULL) {
        free(data_val);
    }

    // Free plist
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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
