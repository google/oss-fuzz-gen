#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" {
    int plist_data_val_compare(plist_t plist, const uint8_t *data, size_t size);
}

extern "C" int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Create a plist object
    plist_t plist = plist_new_dict();

    // Ensure there's data to pass to the function
    if (size == 0) {
        // Clean up and return if no data is available
        plist_free(plist);
        return 0;
    }

    // Call the function-under-test
    int result = plist_data_val_compare(plist, data, size);

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

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
