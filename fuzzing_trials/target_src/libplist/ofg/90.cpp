extern "C" {
    #include <stdint.h>
    #include <stdlib.h>
    #include "/src/libplist/libcnary/include/node.h"
    #include "/src/libplist/include/plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t) * 2) {
        return 0; // Ensure there's enough data for two int32_t values
    }

    // Initialize plist_t
    plist_t plist = plist_new_dict(); // Assuming plist_new_dict() initializes a plist_t object

    // Extract two int32_t values from the input data
    int32_t val1 = *(reinterpret_cast<const int32_t*>(data));
    int32_t val2 = *(reinterpret_cast<const int32_t*>(data + sizeof(int32_t)));

    // Call the function-under-test
    int result = plist_date_val_compare(plist, val1, val2);

    // Clean up
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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
