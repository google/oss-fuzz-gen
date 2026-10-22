// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <H5Gpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>

static hid_t create_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_hid(hid_t id) {
    if (id >= 0) {
        H5Gclose(id);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_file();
    if (file_id < 0) return 0;

    hid_t group_id = -1;
    
    // Fuzz H5Gcreate_anon
    if (Size > 0) {
        hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
        hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
        group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
        H5Pclose(gcpl_id);
        H5Pclose(gapl_id);
    }

    // Fuzz H5Gopen2
    if (Size > 1 && group_id >= 0) {
        char group_name[256];
        snprintf(group_name, sizeof(group_name), "group_%d", Data[0]);
        hid_t open_id = H5Gopen2(file_id, group_name, H5P_DEFAULT);
        close_hid(open_id);
    }

    // Fuzz H5Gcreate2
    if (Size > 2) {
        char group_name[256];
        snprintf(group_name, sizeof(group_name), "group_%d", Data[1]);
        hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
        hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
        hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
        hid_t create_id = H5Gcreate2(file_id, group_name, lcpl_id, gcpl_id, gapl_id);
        H5Pclose(lcpl_id);
        H5Pclose(gcpl_id);
        H5Pclose(gapl_id);
        close_hid(create_id);
    }

    // Fuzz H5Gget_info
    if (Size > 3 && group_id >= 0) {
        H5G_info_t ginfo;
        herr_t status = H5Gget_info(group_id, &ginfo);
        (void)status; // Suppress unused variable warning
    }

    // Fuzz H5Gcreate1
    if (Size > 4) {
        char group_name[256];
        snprintf(group_name, sizeof(group_name), "group_%d", Data[2]);
        hid_t create1_id = H5Gcreate1(file_id, group_name, Data[3]);
        close_hid(create1_id);
    }

    // Fuzz H5Gget_create_plist
    if (Size > 5 && group_id >= 0) {
        hid_t plist_id = H5Gget_create_plist(group_id);
        if (plist_id >= 0) {
            H5Pclose(plist_id);
        }
    }

    close_hid(group_id);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    