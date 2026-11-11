#include <stdint.h>
#include <hdf5.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < 6) {
        return 0;
    }

    // Create a temporary HDF5 file and object to work with
    hid_t file_id = H5Fcreate("temp.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    hid_t group_id = H5Gcreate(file_id, "/group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Extract parameters from the data
    hid_t obj_id = group_id; // Use the created group as the object
    const char* attr_name = (const char*)(data + 1);
    bool exists;
    hid_t es_id = H5EScreate(); // Create an event set for asynchronous operations

    // Ensure null-termination for string parameters
    char attr_name_buf[256];
    strncpy(attr_name_buf, attr_name, sizeof(attr_name_buf) - 1);
    attr_name_buf[sizeof(attr_name_buf) - 1] = '\0';

    // Call the function-under-test
    H5Aexists_async(obj_id, attr_name_buf, &exists, es_id);

    // Clean up
    H5ESclose(es_id);
    H5Gclose(group_id);
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

    LLVMFuzzerTestOneInput_151(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
