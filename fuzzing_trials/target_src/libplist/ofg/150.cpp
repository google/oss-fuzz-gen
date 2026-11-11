#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract a boolean value
    if (size < 1) {
        return 0;
    }

    // Initialize plist
    plist_t plist = plist_new_bool(0); // Initialize with a default boolean value

    // Extract a boolean value from the data
    uint8_t bool_value = data[0] % 2; // Ensure the value is either 0 or 1

    // Call the function-under-test
    plist_set_bool_val(plist, bool_value);

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

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
