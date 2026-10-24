#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>  // Include for 'close' and 'remove'
#include <hdf5.h>

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id;
    H5G_info_t group_info;
    herr_t result;

    // Ensure size is sufficient for creating an HDF5 file
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as an HDF5 file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Create an HDF5 file
    loc_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (loc_id < 0) {
        return 0;
    }

    // Call the function-under-test
    result = H5Gget_info(loc_id, &group_info);

    // Close the HDF5 file
    H5Fclose(loc_id);

    // Remove the temporary file
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
