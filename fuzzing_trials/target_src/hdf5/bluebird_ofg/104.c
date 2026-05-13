#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the parameters
    if (size < 3) {
        return 0;
    }

    // Initialize the parameters
    hid_t dset_id = (hid_t)data[0];
    hid_t es_id = (hid_t)data[1];

    // Call the function-under-test
    herr_t result = H5Dclose_async(dset_id, es_id);

    // Use the result in some way to avoid compiler optimizations
    if (result < 0) {
        // Handle error if needed
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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
