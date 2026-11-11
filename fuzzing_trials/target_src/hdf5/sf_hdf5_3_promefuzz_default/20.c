// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

static void initialize_hdf5() {
    // Initialize HDF5 library
    H5open();
}

static void finalize_hdf5() {
    // Close HDF5 library
    H5close();
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    // Initialize HDF5
    initialize_hdf5();

    if (Size < 1) {
        finalize_hdf5();
        return 0;
    }

    // Create a dummy HDF5 file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        finalize_hdf5();
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "fuzz_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        finalize_hdf5();
        return 0;
    }

    // Prepare data for H5Gget_info_by_name
    H5G_info_t group_info;
    herr_t status = H5Gget_info_by_name(file_id, "fuzz_group", &group_info, H5P_DEFAULT);

    // Handle the return status
    if (status < 0) {
        // Error handling
    }

    // Test H5Gcreate_anon
    hid_t anon_group_id = H5Gcreate_anon(file_id, H5P_DEFAULT, H5P_DEFAULT);
    if (anon_group_id >= 0) {
        // Flush the anonymous group
        H5Gflush(anon_group_id);
        H5Gclose(anon_group_id);
    }

    // Test H5Gflush with the created group
    H5Gflush(group_id);

    // Test H5Gopen2
    hid_t opened_group_id = H5Gopen2(file_id, "fuzz_group", H5P_DEFAULT);
    if (opened_group_id >= 0) {
        H5Gclose(opened_group_id);
    }

    // Test H5Dcreate_anon
    hid_t dataspace_id = H5Screate(H5S_SCALAR);
    hid_t datatype_id = H5Tcopy(H5T_NATIVE_INT);
    hid_t dataset_id = H5Dcreate_anon(file_id, datatype_id, dataspace_id, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Clean up
    H5Sclose(dataspace_id);
    H5Tclose(datatype_id);
    H5Gclose(group_id);
    H5Fclose(file_id);

    // Finalize HDF5
    finalize_hdf5();

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    