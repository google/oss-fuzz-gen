#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>
#include <string.h> // Include this header for memcpy

extern "C" {
    int plist_real_val_compare(plist_t node, double value);
}

extern "C" int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0; // Not enough data to extract a double value
    }

    // Create a plist node of type real
    plist_t node = plist_new_real(0.0);

    // Extract a double value from the input data
    double extracted_value;
    memcpy(&extracted_value, data, sizeof(double));

    // Call the function-under-test
    int result = plist_real_val_compare(node, extracted_value);

    // Clean up the plist node
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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
