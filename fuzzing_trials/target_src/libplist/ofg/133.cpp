#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create a valid plist boolean
    if (size < 1) {
        return 0;
    }

    // Create a plist boolean object based on the input data
    plist_t plist_bool = plist_new_bool(data[0] % 2); // Use the first byte to determine true/false

    // Call the function-under-test
    int result = plist_bool_val_is_true(plist_bool);

    // Check the result to ensure different code paths are exercised
    if (result) {
        // If true, do something (e.g., log, modify, etc.)
    } else {
        // If false, do something else
    }

    // Clean up
    plist_free(plist_bool);

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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
