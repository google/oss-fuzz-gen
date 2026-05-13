#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < 1) {
        return 0;
    }

    // Prepare the parameters for H5Dget_space_async
    hid_t dset_id = (hid_t)data[0]; // Use the first byte of data for dset_id

    // Create HDF5 identifiers
    hid_t dxpl_id = H5Pcreate(H5P_DATASET_XFER);
    hid_t es_id = H5EScreate();

    // Call the function-under-test
    hid_t result = H5Dget_space_async(dset_id, es_id);

    // Clean up resources
    H5Pclose(dxpl_id);
    H5ESclose(es_id);

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

    LLVMFuzzerTestOneInput_236(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
