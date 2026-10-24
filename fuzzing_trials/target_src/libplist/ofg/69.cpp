#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for two int32_t values
    if (size < 2 * sizeof(int32_t)) {
        return 0;
    }

    // Extract two int32_t values from the input data
    int32_t sec = *(reinterpret_cast<const int32_t*>(data));
    int32_t usec = *(reinterpret_cast<const int32_t*>(data + sizeof(int32_t)));

    // Call the function-under-test
    plist_t plist = plist_new_date(sec, usec);

    // Free the plist if it was successfully created
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
