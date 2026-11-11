#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure that we have enough data to work with
    if (size < 3) return 0;

    // Initialize HDF5 library
    H5open();

    // Create a temporary file to work with
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a dummy group to ensure there's something to delete
    hid_t group_id = H5Gcreate2(file_id, "/dummy_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }
    H5Gclose(group_id);

    // Use parts of the data as the object name and attribute name
    size_t name_len = size / 2;
    size_t attr_len = size - name_len;

    char *object_name = (char *)malloc(name_len + 1);
    char *attr_name = (char *)malloc(attr_len + 1);

    if (!object_name || !attr_name) {
        free(object_name);
        free(attr_name);
        H5Fclose(file_id);
        return 0;
    }

    memcpy(object_name, data, name_len);
    object_name[name_len] = '\0';

    memcpy(attr_name, data + name_len, attr_len);
    attr_name[attr_len] = '\0';

    // Call the function-under-test
    H5Adelete_by_name(file_id, object_name, attr_name, H5P_DEFAULT);

    // Cleanup
    free(object_name);
    free(attr_name);
    H5Fclose(file_id);
    H5close();

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
