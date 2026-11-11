#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize a plist object
    plist_t plist = NULL;

    // Create a plist from the input data
    plist_format_t format;
    plist_from_memory((const char*)data, size, &plist, &format);

    // Ensure the plist is of dictionary type
    if (plist && plist_get_node_type(plist) == PLIST_DICT) {
        // Call the function-under-test
        uint32_t dict_size = plist_dict_get_size(plist);

        // Optionally, perform operations with dict_size
        (void)dict_size; // Suppress unused variable warning
    }

    // Free the plist object
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
