#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" {
    #include <string.h> // Include the library for memcpy

    int plist_real_val_compare(plist_t node, double value);
}

extern "C" int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract a double value
    if (size < sizeof(double)) {
        return 0;
    }

    // Create a plist node with a real value
    plist_t node = plist_new_real(0.0);

    // Extract a double value from the input data
    double extracted_value;
    memcpy(&extracted_value, data, sizeof(double));

    // Call the function-under-test
    int result = plist_real_val_compare(node, extracted_value);

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

    LLVMFuzzerTestOneInput_157(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
