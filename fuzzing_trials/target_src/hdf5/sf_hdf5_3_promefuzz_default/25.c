// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
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
#include <H5Ppublic.h>
#include <H5Fpublic.h>
#include <H5Opublic.h>

static void fuzz_H5Gget_create_plist(hid_t group_id) {
    hid_t plist_id = H5Gget_create_plist(group_id);
    if (plist_id != H5I_INVALID_HID) {
        H5Pclose(plist_id);
    }
}

static void fuzz_H5Gcreate_anon(hid_t loc_id) {
    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    hid_t group_id = H5Gcreate_anon(loc_id, gcpl_id, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
}

static void fuzz_H5Gflush(hid_t group_id) {
    H5Gflush(group_id);
}

static void fuzz_H5Gopen2(hid_t loc_id, const char *name) {
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    hid_t group_id = H5Gopen2(loc_id, name, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
    H5Pclose(gapl_id);
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name) {
    hid_t lcpl_id = H5Pcreate(H5P_LINK_CREATE);
    hid_t gcpl_id = H5Pcreate(H5P_GROUP_CREATE);
    hid_t gapl_id = H5Pcreate(H5P_GROUP_ACCESS);
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
    H5Pclose(lcpl_id);
    H5Pclose(gcpl_id);
    H5Pclose(gapl_id);
}

static void fuzz_H5Gcreate1(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gcreate1(loc_id, name, 0);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    char *group_name = (char *)malloc(Size + 1);
    if (!group_name) {
        H5Fclose(file_id);
        return 0;
    }
    memcpy(group_name, Data, Size);
    group_name[Size] = '\0';

    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        fuzz_H5Gget_create_plist(group_id);
        fuzz_H5Gcreate_anon(file_id);
        fuzz_H5Gflush(group_id);
        fuzz_H5Gopen2(file_id, group_name);
        fuzz_H5Gcreate2(file_id, group_name);
        fuzz_H5Gcreate1(file_id, group_name);
        H5Gclose(group_id);
    }

    free(group_name);
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    