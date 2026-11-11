#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure the input size is non-zero and manageable
    if (size == 0 || size > 65535) {
        return 0;
    }

    // Allocate memory for the binary data input
    char *bin_data = (char *)malloc(size + 1);
    if (!bin_data) {
        return 0;
    }

    // Copy the input data to the binary data buffer
    memcpy(bin_data, data, size);
    bin_data[size] = '\0'; // Null-terminate to ensure safety

    // Initialize a plist_t object
    plist_t plist = NULL;

    // Call the function-under-test
    plist_err_t result = plist_from_bin(bin_data, (uint32_t)size, &plist);

    // Clean up
    free(bin_data);
    if (plist) {
        plist_free(plist);
    }

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
