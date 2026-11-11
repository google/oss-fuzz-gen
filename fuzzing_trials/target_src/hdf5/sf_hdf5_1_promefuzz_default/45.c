// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hdf5.h"
#include "H5Gpublic.h"

static void handle_error(herr_t status) {
    if (status < 0) {
        fprintf(stderr, "HDF5 function call failed\n");
        exit(1);
    }
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file and initialize HDF5 library
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create a group to use with H5G functions
    hid_t group_id = H5Gcreate2(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Grefresh
    herr_t status = H5Grefresh(group_id);
    handle_error(status);

    // Fuzz H5Gget_info
    H5G_info_t ginfo;
    status = H5Gget_info(group_id, &ginfo);
    handle_error(status);

    // Fuzz H5Gget_info_by_name
    status = H5Gget_info_by_name(file_id, "test_group", &ginfo, H5P_DEFAULT);
    handle_error(status);

    // Fuzz H5Gget_info_by_idx
    status = H5Gget_info_by_idx(file_id, ".", H5_INDEX_NAME, H5_ITER_INC, 0, &ginfo, H5P_DEFAULT);
    handle_error(status);

    // Fuzz H5Gflush
    status = H5Gflush(group_id);
    handle_error(status);

    // Clean up resources
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
    