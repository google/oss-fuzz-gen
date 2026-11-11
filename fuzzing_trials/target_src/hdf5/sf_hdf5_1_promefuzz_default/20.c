// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
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
#include "H5Gpublic.h"
#include "H5Ppublic.h"
#include "H5Fpublic.h"

static hid_t create_file() {
    return H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
}

static void close_file(hid_t file_id) {
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
}

static void fuzz_H5Gcreate_anon(hid_t file_id) {
    hid_t group_id = H5Gcreate_anon(file_id, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gopen2(hid_t file_id) {
    hid_t group_id = H5Gcreate2(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
    hid_t opened_group_id = H5Gopen2(file_id, "test_group", H5P_DEFAULT);
    if (opened_group_id >= 0) {
        H5Gclose(opened_group_id);
    }
}

static void fuzz_H5Gcreate2(hid_t file_id) {
    hid_t group_id = H5Gcreate2(file_id, "test_group_2", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info(hid_t file_id) {
    hid_t group_id = H5Gcreate2(file_id, "test_group_3", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5G_info_t ginfo;
        if (H5Gget_info(group_id, &ginfo) >= 0) {
            // Successfully retrieved group info
        }
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gcreate1(hid_t file_id) {
    hid_t group_id = H5Gcreate1(file_id, "test_group_4", 0);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_create_plist(hid_t file_id) {
    hid_t group_id = H5Gcreate2(file_id, "test_group_5", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        hid_t plist_id = H5Gget_create_plist(group_id);
        if (plist_id >= 0) {
            H5Pclose(plist_id);
        }
        H5Gclose(group_id);
    }
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_file();
    if (file_id < 0) {
        return 0;
    }

    fuzz_H5Gcreate_anon(file_id);
    fuzz_H5Gopen2(file_id);
    fuzz_H5Gcreate2(file_id);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Gcreate1(file_id);
    fuzz_H5Gget_create_plist(file_id);

    close_file(file_id);
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
    