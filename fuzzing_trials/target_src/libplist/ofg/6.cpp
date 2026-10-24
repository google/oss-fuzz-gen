#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Initialize plist_t and plist_dict_iter
    plist_t plist;
    plist_dict_iter iter;

    // Create a plist node from the input data
    plist_from_bin((const char*)data, size, &plist);

    // Ensure plist is not NULL
    if (plist == NULL) {
        // If plist creation failed, create an empty dictionary
        plist = plist_new_dict();
    }

    // Call the function-under-test
    plist_dict_new_iter(plist, &iter);

    // Free the plist node
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
