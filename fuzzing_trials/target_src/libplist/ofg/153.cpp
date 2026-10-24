#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include the string.h library for memcpy

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract an int64_t value
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Initialize a plist object
    plist_t plist = plist_new_dict();

    // Extract an int64_t value from the input data
    int64_t int_value;
    memcpy(&int_value, data, sizeof(int64_t));

    // Call the function-under-test
    plist_set_int_val(plist, int_value);

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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
