#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating an HDF5 file
    if (size < 1) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id;
    char filename[] = "tempfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Create an HDF5 file
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Prepare the output variable
    unsigned long fileno = 0;

    // Call the function-under-test
    herr_t status = H5Fget_fileno(file_id, &fileno);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Remove the temporary file
    remove(filename);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
