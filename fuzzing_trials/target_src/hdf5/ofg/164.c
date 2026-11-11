#include <stdint.h>
#include <hdf5.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    hid_t file_id;
    hid_t plist_id;

    // Ensure the data size is sufficient for creating a filename
    if (size < 5) {
        return 0;
    }

    // Create a temporary filename from the input data
    char filename[6];
    snprintf(filename, sizeof(filename), "/tmp/%c%c%c%c%c", data[0], data[1], data[2], data[3], data[4]);

    // Create a new HDF5 file using the filename
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Call the function-under-test
    plist_id = H5Fget_create_plist(file_id);

    // Close the file and property list if they were successfully created
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }
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

    LLVMFuzzerTestOneInput_164(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
