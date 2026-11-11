#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_271(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a valid string
    if (size < 1) return 0;

    // Create a temporary file to act as an HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group in the file
    hid_t group_id = H5Gcreate(file_id, "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Close the group as it is not needed after creation
    H5Gclose(group_id);

    // Convert the input data to a null-terminated string
    char *group_name = (char *)malloc(size + 1);
    if (group_name == NULL) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(group_name, data, size);
    group_name[size] = '\0';

    // Call the function-under-test
    H5Gunlink(file_id, group_name);

    // Clean up
    free(group_name);
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

    LLVMFuzzerTestOneInput_271(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
