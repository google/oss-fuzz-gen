#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    // Use the first byte of data to create a boolean plist
    uint8_t bool_value = data[0];

    // Call the function-under-test
    plist_t plist = plist_new_bool(bool_value);

    // Clean up the plist object to prevent memory leaks
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

    LLVMFuzzerTestOneInput_181(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
