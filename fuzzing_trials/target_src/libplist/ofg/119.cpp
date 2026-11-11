#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" int plist_int_val_is_negative(plist_t node);

extern "C" int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    // Initialize a plist node
    plist_t node = plist_new_dict();

    if (size >= sizeof(int64_t)) {
        // Extract an integer value from the input data
        int64_t value = 0;
        for (size_t i = 0; i < sizeof(int64_t); ++i) {
            value |= ((int64_t)data[i] << (i * 8));
        }

        // Add an integer key-value pair to the plist node
        plist_dict_set_item(node, "key", plist_new_int(value));

        // Call the function-under-test
        plist_int_val_is_negative(node);
    }

    // Free the plist node
    plist_free(node);

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

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
