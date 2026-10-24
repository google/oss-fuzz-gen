#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract an hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract hid_t from the input data
    hid_t dataset_id = *(const hid_t *)data;

    // Call the function-under-test
    hid_t dataspace_id = H5Dget_space(dataset_id);

    // Perform cleanup if dataspace_id is valid
    if (dataspace_id >= 0) {
        H5Sclose(dataspace_id);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_39(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
