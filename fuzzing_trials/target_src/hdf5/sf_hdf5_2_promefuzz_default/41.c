// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dget_create_plist at H5D.c:747:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>

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

static void fuzz_H5Dget_create_plist(hid_t dset_id) {
    hid_t plist_id = H5Dget_create_plist(dset_id);
    if (plist_id != H5I_INVALID_HID) {
        H5Pclose(plist_id);
    }
}

static void fuzz_H5Dopen2(hid_t loc_id, const char *name, hid_t dapl_id) {
    hid_t dset_id = H5Dopen2(loc_id, name, dapl_id);
    if (dset_id != H5I_INVALID_HID) {
        H5Dclose(dset_id);
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name, hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id) {
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Dcreate2(hid_t loc_id, const char *name, hid_t type_id, hid_t space_id, hid_t lcpl_id, hid_t dcpl_id, hid_t dapl_id) {
    hid_t dset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dset_id != H5I_INVALID_HID) {
        H5Dclose(dset_id);
    }
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) + 1) return 0;

    hid_t loc_id = *((hid_t *)Data);
    const char *name = (const char *)(Data + sizeof(hid_t));
    hid_t plist_id = H5P_DEFAULT;

    // Fuzz each function with the provided input
    fuzz_H5Gget_create_plist(loc_id);
    fuzz_H5Gopen2(loc_id, name, plist_id);
    fuzz_H5Dget_create_plist(loc_id);
    fuzz_H5Dopen2(loc_id, name, plist_id);
    fuzz_H5Gcreate2(loc_id, name, plist_id, plist_id, plist_id);
    fuzz_H5Dcreate2(loc_id, name, H5T_NATIVE_INT, H5S_ALL, plist_id, plist_id, plist_id);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    