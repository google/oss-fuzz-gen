extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Initialize a plist node from the input data
    plist_t node = NULL;
    if (size > 0) {
        plist_from_bin((const char*)data, size, &node);
    }

    // Ensure the node is not NULL before calling plist_get_parent
    if (node != NULL) {
        // Call the function-under-test
        plist_t parent = plist_get_parent(node);

        // Clean up
        plist_free(parent);
        plist_free(node);
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
