// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
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

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id, group_id, gcpl_id, gapl_id, lcpl_id;
    H5G_info_t group_info;
    herr_t status;
    char group_name[256];

    const char *filename = "./dummy_file";
    write_dummy_file(filename);

    // Create a new file using default properties.
    file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Use some data from the input to create group names
    snprintf(group_name, sizeof(group_name), "group_%u", Data[0]);

    // Create property lists
    gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    lcpl_id = H5Pcreate(H5P_LINK_CREATE);

    // Fuzz H5Gcreate_anon
    group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Gcreate2
    group_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Gopen2
    group_id = H5Gopen2(file_id, group_name, gapl_id);
    if (group_id >= 0) {
        // Fuzz H5Gget_info
        status = H5Gget_info(group_id, &group_info);
        
        // Fuzz H5Gget_create_plist
        hid_t plist_id = H5Gget_create_plist(group_id);
        if (plist_id >= 0) {
            H5Pclose(plist_id);
        }

        H5Gclose(group_id);
    }

    // Fuzz H5Gcreate1 (deprecated)
    group_id = H5Gcreate1(file_id, group_name, 0);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Cleanup
    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
    H5Pclose(lcpl_id);
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    