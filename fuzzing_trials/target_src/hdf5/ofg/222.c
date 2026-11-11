#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_222(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for two null-terminated strings
    if (size < 4) {
        return 0;
    }

    // Create a temporary HDF5 file
    hid_t file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create two groups in the file
    hid_t group1_id = H5Gcreate2(file_id, "/group1", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    hid_t group2_id = H5Gcreate2(file_id, "/group2", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    if (group1_id < 0 || group2_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Split data into two strings
    size_t len1 = data[0] % (size - 1) + 1; // Ensure at least 1 character
    size_t len2 = size - len1 - 1;

    char *name1 = (char *)malloc(len1 + 1);
    char *name2 = (char *)malloc(len2 + 1);

    if (name1 == NULL || name2 == NULL) {
        free(name1);
        free(name2);
        H5Gclose(group1_id);
        H5Gclose(group2_id);
        H5Fclose(file_id);
        return 0;
    }

    memcpy(name1, data + 1, len1);
    name1[len1] = '\0';

    memcpy(name2, data + 1 + len1, len2);
    name2[len2] = '\0';

    // Call the function-under-test
    H5Gmove2(group1_id, name1, group2_id, name2);

    // Clean up
    free(name1);
    free(name2);
    H5Gclose(group1_id);
    H5Gclose(group2_id);
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

    LLVMFuzzerTestOneInput_222(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
