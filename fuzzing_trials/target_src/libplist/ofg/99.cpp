extern "C" {
    #include <stdint.h>
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to extract a uint64_t value
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t uid = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        uid |= ((uint64_t)data[i] << (i * 8));
    }

    // Call the function-under-test
    plist_t plist = plist_new_uid(uid);

    // Clean up the plist object if it was created
    if (plist != nullptr) {
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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
