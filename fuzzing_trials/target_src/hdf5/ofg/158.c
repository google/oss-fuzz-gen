#include <stdint.h>
#include <stdio.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    hid_t file_id;
    herr_t status;

    // Ensure the data size is sufficient for a filename
    if (size < 1) {
        return 0;
    }

    // Create a temporary filename using the provided data
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzzfile_%.*s.h5", (int)size, data);

    // Create a new HDF5 file using the filename
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Call the function-under-test
    status = H5Fstart_swmr_write(file_id);

    // Close the file
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
