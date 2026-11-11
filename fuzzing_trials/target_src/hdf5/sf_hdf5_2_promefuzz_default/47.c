// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_create_plist at H5G.c:501:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
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
#include <stdlib.h>
#include <string.h>
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

static void fuzz_H5Glink2(hid_t cur_loc_id, const char *cur_name, H5L_type_t type, hid_t new_loc_id, const char *new_name) {
    H5Glink2(cur_loc_id, cur_name, type, new_loc_id, new_name);
}

static void fuzz_H5Dcreate_anon(hid_t loc_id, hid_t type_id, hid_t space_id, hid_t dcpl_id, hid_t dapl_id) {
    hid_t dataset_id = H5Dcreate_anon(loc_id, type_id, space_id, dcpl_id, dapl_id);
    if (dataset_id != H5I_INVALID_HID) {
        H5Dclose(dataset_id);
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name, hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id) {
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id != H5I_INVALID_HID) {
        H5Gclose(group_id);
    }
}

static void fuzz_H5Dcreate2(hid_t loc_id, const char *name, hid_t type_id, hid_t space_id, hid_t lcpl_id, hid_t dcpl_id, hid_t dapl_id) {
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id != H5I_INVALID_HID) {
        H5Dclose(dataset_id);
    }
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    hid_t loc_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < 1) return 0;
    const char *name = (const char *)Data;
    size_t name_len = strnlen(name, Size);
    if (name_len == Size) return 0;
    Data += name_len + 1;
    Size -= name_len + 1;

    if (Size < sizeof(hid_t)) return 0;
    hid_t type_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(hid_t)) return 0;
    hid_t space_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(hid_t)) return 0;
    hid_t lcpl_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(hid_t)) return 0;
    hid_t dcpl_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(hid_t)) return 0;
    hid_t dapl_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(H5L_type_t)) return 0;
    H5L_type_t link_type = *(H5L_type_t *)Data;
    Data += sizeof(H5L_type_t);
    Size -= sizeof(H5L_type_t);

    if (Size < 1) return 0;
    const char *cur_name = (const char *)Data;
    size_t cur_name_len = strnlen(cur_name, Size);
    if (cur_name_len == Size) return 0;
    Data += cur_name_len + 1;
    Size -= cur_name_len + 1;

    if (Size < 1) return 0;
    const char *new_name = (const char *)Data;
    size_t new_name_len = strnlen(new_name, Size);
    if (new_name_len == Size) return 0;

    fuzz_H5Gget_create_plist(loc_id);
    fuzz_H5Gopen2(loc_id, name, dapl_id);
    fuzz_H5Glink2(loc_id, cur_name, link_type, loc_id, new_name);
    fuzz_H5Dcreate_anon(loc_id, type_id, space_id, dcpl_id, dapl_id);
    fuzz_H5Gcreate2(loc_id, name, lcpl_id, dcpl_id, dapl_id);
    fuzz_H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    