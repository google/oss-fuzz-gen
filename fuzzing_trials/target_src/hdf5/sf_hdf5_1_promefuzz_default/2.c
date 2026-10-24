// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h"  // Include this header for H5P_DEFAULT

static const char *dummy_file = "./dummy_file";

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a file
    hid_t file_id = H5Fcreate(dummy_file, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group
    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%zu", Size);
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get creation property list of the group
    hid_t gcpl_id = H5Gget_create_plist(group_id);
    if (gcpl_id >= 0) {
        H5Pclose(gcpl_id);
    }

    // Get group information
    H5G_info_t ginfo;
    herr_t status = H5Gget_info(group_id, &ginfo);

    // Get group information by name
    status = H5Gget_info_by_name(file_id, group_name, &ginfo, H5P_DEFAULT);

    // Get group information by index
    status = H5Gget_info_by_idx(file_id, ".", H5_INDEX_NAME, H5_ITER_INC, 0, &ginfo, H5P_DEFAULT);

    // Cleanup
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    