#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a valid string
    if (size < 1) return 0;

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Allocate a buffer for the file name
    size_t buf_size = size < 256 ? size : 256; // Limit buffer size to 256
    char *name_buf = (char *)malloc(buf_size);
    if (name_buf == NULL) {
        H5Fclose(file_id);
        return 0;
    }

    // Call the function-under-test
    ssize_t name_len = H5Fget_name(file_id, name_buf, buf_size);

    // Clean up
    free(name_buf);
    H5Fclose(file_id);
    remove("tempfile.h5");

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
