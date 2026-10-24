extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "/src/libplist/include/plist/plist.h"
}

// Declare missing functions based on typical plist library usage
extern "C" {
    plist_t plist_new_data(const char *val, uint64_t length);
    void plist_free(plist_t plist);
    void plist_print(plist_t plist);
}

extern "C" int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Initialize a plist_t object from data
    plist_t plist = plist_new_data((const char*)data, (uint64_t)size);

    // Check if the plist is successfully created
    if (plist == NULL) {
        return 0; // Exit if plist creation failed
    }

    // Call the function-under-test
    plist_print(plist);

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

    LLVMFuzzerTestOneInput_182(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
