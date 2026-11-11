// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
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

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_resources(hid_t *resources, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (resources[i] >= 0) {
            H5Gclose(resources[i]);
        }
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    hid_t lapl_id = H5Pcreate(H5P_LINK_ACCESS);

    hid_t group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
    if (group_id < 0) goto cleanup;

    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%zu", Size);

    H5G_info_t ginfo;
    H5Gget_info_by_idx(file_id, group_name, H5_INDEX_NAME, H5_ITER_INC, 0, &ginfo, lapl_id);
    H5Gopen2(file_id, group_name, gapl_id);
    H5Gget_info_by_name(file_id, group_name, &ginfo, lapl_id);
    H5Gget_info(group_id, &ginfo);
    H5Gflush(group_id);

cleanup:
    hid_t resources[] = {group_id, gcpl_id, gapl_id, lapl_id, file_id};
    close_resources(resources, sizeof(resources) / sizeof(resources[0]));

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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    