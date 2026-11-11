// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
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
#include "H5Gpublic.h"
#include "H5Fpublic.h"
#include "H5Ppublic.h"
#include "H5Tpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);

    if (gcpl_id < 0 || gapl_id < 0 || lcpl_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Gcreate_anon
    hid_t anon_group_id = H5Gcreate_anon(file_id, gcpl_id, gapl_id);
    if (anon_group_id >= 0) {
        H5Gclose(anon_group_id);
    }

    // Fuzz H5Gopen2
    char name_buffer[256];
    snprintf(name_buffer, sizeof(name_buffer), "group_%zu", Size);
    hid_t group_id = H5Gcreate2(file_id, name_buffer, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        hid_t opened_group_id = H5Gopen2(file_id, name_buffer, gapl_id);
        if (opened_group_id >= 0) {
            H5Gclose(opened_group_id);
        }
        H5Gclose(group_id);
    }

    // Fuzz H5Gget_info
    H5G_info_t ginfo;
    herr_t info_status = H5Gget_info(file_id, &ginfo);

    // Fuzz H5Gcreate1
    hid_t group_id1 = H5Gcreate1(file_id, name_buffer, 0);
    if (group_id1 >= 0) {
        H5Gclose(group_id1);
    }

    // Fuzz H5Gget_create_plist
    hid_t create_plist_id = H5Gget_create_plist(file_id);
    if (create_plist_id >= 0) {
        H5Pclose(create_plist_id);
    }

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    