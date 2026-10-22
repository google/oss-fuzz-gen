#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a memory buffer to act as a file
    hid_t fapl = H5Pcreate(H5P_FILE_ACCESS);
    H5Pset_fapl_core(fapl, (size_t)size, false);

    // Create a new file using the memory buffer
    hid_t file_id = H5Fcreate("fuzz_test_file", H5F_ACC_TRUNC, H5P_DEFAULT, fapl);

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "/fuzz_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    // Prepare the H5G_info_t structure
    H5G_info_t group_info;

    // Call the function-under-test with the group ID and the group_info structure
    herr_t status = H5Gget_info(group_id, &group_info);

    // Cleanup
    H5Gclose(group_id);
    H5Fclose(file_id);
    H5Pclose(fapl);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
