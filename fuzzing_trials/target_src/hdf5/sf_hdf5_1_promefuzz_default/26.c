// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
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
#include "H5Gpublic.h"

static void fuzz_H5Gcreate_anon(hid_t loc_id) {
    hid_t gcpl_id = H5P_DEFAULT; // Group creation property list
    hid_t gapl_id = H5P_DEFAULT; // Group access property list

    hid_t group_id = H5Gcreate_anon(loc_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info_by_idx(hid_t loc_id) {
    const char *group_name = ".";
    H5_index_t idx_type = H5_INDEX_NAME;
    H5_iter_order_t order = H5_ITER_INC; // Assuming H5_ITER_INC is defined
    hsize_t n = 0;
    H5G_info_t ginfo;
    hid_t lapl_id = H5P_DEFAULT;

    herr_t status = H5Gget_info_by_idx(loc_id, group_name, idx_type, order, n, &ginfo, lapl_id);
    (void)status; // Suppress unused variable warning
}

static void fuzz_H5Gopen2(hid_t loc_id) {
    const char *name = ".";
    hid_t gapl_id = H5P_DEFAULT;

    hid_t group_id = H5Gopen2(loc_id, name, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info_by_name(hid_t loc_id) {
    const char *name = ".";
    H5G_info_t ginfo;
    hid_t lapl_id = H5P_DEFAULT;

    herr_t status = H5Gget_info_by_name(loc_id, name, &ginfo, lapl_id);
    (void)status; // Suppress unused variable warning
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;

    herr_t status = H5Gget_info(loc_id, &ginfo);
    (void)status; // Suppress unused variable warning
}

static void fuzz_H5Gflush(hid_t group_id) {
    herr_t status = H5Gflush(group_id);
    (void)status; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    // Create a dummy file to work with
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Fuzz each target function
    fuzz_H5Gcreate_anon(file_id);
    fuzz_H5Gget_info_by_idx(file_id);
    fuzz_H5Gopen2(file_id);
    fuzz_H5Gget_info_by_name(file_id);
    fuzz_H5Gget_info(file_id);

    // Create a group to test H5Gflush
    hid_t group_id = H5Gcreate(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        fuzz_H5Gflush(group_id);
        H5Gclose(group_id);
    }

    // Close the file
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    