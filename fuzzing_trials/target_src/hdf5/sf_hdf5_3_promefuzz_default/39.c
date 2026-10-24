// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gopen1 at H5Gdeprec.c:247:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dopen1 at H5Ddeprec.c:166:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

static void fuzz_H5Gopen1(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gopen1(loc_id, name);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Dopen1(hid_t loc_id, const char *name) {
    hid_t dataset_id = H5Dopen1(loc_id, name);
    if (dataset_id != H5I_INVALID_HID) {
        H5Dclose(dataset_id);
    }
}

static void fuzz_H5Gget_create_plist(hid_t group_id) {
    hid_t plist_id = H5Gget_create_plist(group_id);
    if (plist_id != H5I_INVALID_HID) {
        H5Pclose(plist_id);
    }
}

static void fuzz_H5Gopen2(hid_t loc_id, const char *name, hid_t gapl_id) {
    hid_t group_id = H5Gopen2(loc_id, name, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name, hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id) {
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gcreate1(hid_t loc_id, const char *name, size_t size_hint) {
    hid_t group_id = H5Gcreate1(loc_id, name, size_hint);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t loc_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (loc_id < 0) return 0;

    char *name = (char *)malloc(Size + 1);
    if (!name) {
        H5Fclose(loc_id);
        return 0;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    fuzz_H5Gopen1(loc_id, name);
    fuzz_H5Dopen1(loc_id, name);
    fuzz_H5Gget_create_plist(loc_id);
    fuzz_H5Gopen2(loc_id, name, H5P_DEFAULT);
    fuzz_H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    fuzz_H5Gcreate1(loc_id, name, (size_t)Size);

    free(name);
    H5Fclose(loc_id);
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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    