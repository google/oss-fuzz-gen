#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" {
    plist_t plist_new_data(const char *val, uint64_t length);
    int plist_data_val_compare(plist_t, const uint8_t *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Ensure data is not null and size is greater than 0
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Initialize a plist node
    plist_t plist_node = plist_new_data(reinterpret_cast<const char *>(data), size);

    // Call the function-under-test
    int result = plist_data_val_compare(plist_node, data, size);

    // Clean up
    plist_free(plist_node);

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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
