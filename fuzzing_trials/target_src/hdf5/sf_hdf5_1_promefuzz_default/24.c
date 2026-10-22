// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <hdf5.h>
#include "H5Gpublic.h"

static hid_t create_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create HDF5 file\n");
        exit(EXIT_FAILURE);
    }
    return file_id;
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_file();
    hid_t group_id, gcpl_id, gapl_id, lapl_id;
    H5G_info_t ginfo;
    H5_index_t idx_type;
    H5_iter_order_t order;
    hsize_t n = 0;

    gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    lapl_id = H5Pcreate(H5P_LINK_ACCESS);

    // Fuzz H5Gcreate_anon
    group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Gget_info_by_idx
    idx_type = (H5_index_t)(Data[0] % H5_INDEX_N);
    order = (H5_iter_order_t)(Data[0] % 3); // Assuming 3 orders: increasing, decreasing, native
    if (H5Gget_info_by_idx(file_id, ".", idx_type, order, n, &ginfo, lapl_id) >= 0) {
        // Do something with ginfo if needed
    }

    // Fuzz H5Gopen2
    group_id = H5Gopen2(file_id, ".", gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Gget_info_by_name
    if (H5Gget_info_by_name(file_id, ".", &ginfo, lapl_id) >= 0) {
        // Do something with ginfo if needed
    }

    // Fuzz H5Gget_info
    if (H5Gget_info(file_id, &ginfo) >= 0) {
        // Do something with ginfo if needed
    }

    // Fuzz H5Gflush
    group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gflush(group_id);
        H5Gclose(group_id);
    }

    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
    H5Pclose(lapl_id);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    