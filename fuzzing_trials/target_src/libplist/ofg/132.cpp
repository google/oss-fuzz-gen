#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    int plist_bool_val_is_true(plist_t node);
}

extern "C" int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Create a plist node
    plist_t node = plist_new_bool(false);

    // Ensure the data is not empty and is at least 1 byte
    if (size > 0) {
        // Set the boolean value based on the first byte of data
        bool value = data[0] % 2 == 0; // Even byte value is true, odd is false
        plist_set_bool_val(node, value);
    }

    // Call the function-under-test
    int result = plist_bool_val_is_true(node);

    // Clean up
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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
