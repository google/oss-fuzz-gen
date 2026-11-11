#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extracting hid_t from the input data
    hid_t dataset_id = *((hid_t *)data);

    // Initialize H5D_space_status_t
    H5D_space_status_t space_status;

    // Call the function-under-test
    herr_t status = H5Dget_space_status(dataset_id, &space_status);

    // Handle the return status if needed (for debugging purposes, etc.)
    // For now, just ignore it

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_245(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
