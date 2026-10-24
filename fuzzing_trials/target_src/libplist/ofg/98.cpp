#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t uid = *(const uint64_t *)data;

    // Call the function-under-test
    plist_t plist = plist_new_uid(uid);

    // Clean up if necessary
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
