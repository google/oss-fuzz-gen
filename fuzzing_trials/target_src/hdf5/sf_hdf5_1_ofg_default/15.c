#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    if (H5open() < 0) {
        return 0;
    }

    // Create a temporary HDF5 file in memory
    hid_t fapl_id = H5Pcreate(H5P_FILE_ACCESS);
    H5Pset_fapl_core(fapl_id, (size_t)1024, 0);
    hid_t file_id = H5Fcreate("tempfile", H5F_ACC_TRUNC, H5P_DEFAULT, fapl_id);

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Prepare H5G_info_t structure
    H5G_info_t group_info;

    // Call the function-under-test
    herr_t status = H5Gget_info(group_id, &group_info);

    // Close the group and file
    H5Gclose(group_id);
    H5Fclose(file_id);
    H5Pclose(fapl_id);

    // Close HDF5 library
    H5close();

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
