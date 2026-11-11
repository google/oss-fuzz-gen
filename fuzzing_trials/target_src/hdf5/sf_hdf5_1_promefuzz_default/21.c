// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gcreate1 at H5Gdeprec.c:153:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Gpublic.h"
#include "H5Ppublic.h"

static void fuzz_H5Gcreate_anon(hid_t loc_id) {
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;
    hid_t group_id = H5Gcreate_anon(loc_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gopen2(hid_t loc_id, const char *name) {
    hid_t gapl_id = H5P_DEFAULT;
    hid_t group_id = H5Gopen2(loc_id, name, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name) {
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    if (H5Gget_info(loc_id, &ginfo) >= 0) {
        // Successfully retrieved group info
    }
}

static void fuzz_H5Gcreate1(hid_t loc_id, const char *name, size_t size_hint) {
    hid_t group_id = H5Gcreate1(loc_id, name, size_hint);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Gget_create_plist(hid_t group_id) {
    hid_t plist_id = H5Gget_create_plist(group_id);
    if (plist_id >= 0) {
        H5Pclose(plist_id);
    }
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file for HDF5 operations
    FILE *file = fopen("./dummy_file", "w+");
    if (!file) return 0;
    fclose(file);

    // Use a dummy location id for fuzzing purposes
    hid_t loc_id = 0;

    // Use the data to create a string for group names
    char *name = (char *)malloc(Size + 1);
    if (!name) return 0;
    memcpy(name, Data, Size);
    name[Size] = '\0';

    // Fuzz each function
    fuzz_H5Gcreate_anon(loc_id);
    fuzz_H5Gopen2(loc_id, name);
    fuzz_H5Gcreate2(loc_id, name);
    fuzz_H5Gget_info(loc_id);
    fuzz_H5Gcreate1(loc_id, name, Size);
    fuzz_H5Gget_create_plist(loc_id);

    free(name);
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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    