// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate_anon at H5D.c:273:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Fpublic.h>

static void fuzz_H5Gget_info_by_name(hid_t loc_id, const char *name) {
    H5G_info_t ginfo;
    if (H5Gget_info_by_name(loc_id, name, &ginfo, H5P_DEFAULT) < 0) {
        fprintf(stderr, "H5Gget_info_by_name failed for group: %s\n", name);
    }
}

static void fuzz_H5Gcreate_anon(hid_t loc_id) {
    hid_t group_id = H5Gcreate_anon(loc_id, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    } else {
        fprintf(stderr, "H5Gcreate_anon failed\n");
    }
}

static void fuzz_H5Gflush(hid_t group_id) {
    if (H5Gflush(group_id) < 0) {
        fprintf(stderr, "H5Gflush failed for group_id: %lld\n", (long long)group_id);
    }
}

static void fuzz_H5Gopen2(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gopen2(loc_id, name, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    } else {
        fprintf(stderr, "H5Gopen2 failed for group: %s\n", name);
    }
}

static void fuzz_H5Dcreate_anon(hid_t loc_id, hid_t type_id, hid_t space_id) {
    hid_t dataset_id = H5Dcreate_anon(loc_id, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    } else {
        fprintf(stderr, "H5Dcreate_anon failed\n");
    }
}

static void fuzz_H5Gcreate2(hid_t loc_id, const char *name) {
    hid_t group_id = H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    } else {
        fprintf(stderr, "H5Gcreate2 failed for group: %s\n", name);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%zu", Size);

    fuzz_H5Gget_info_by_name(file_id, group_name);
    fuzz_H5Gcreate_anon(file_id);
    fuzz_H5Gflush(file_id);
    fuzz_H5Gopen2(file_id, group_name);

    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);

    fuzz_H5Dcreate_anon(file_id, type_id, space_id);

    fuzz_H5Gcreate2(file_id, group_name);

    H5Sclose(space_id);
    H5Tclose(type_id);
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
    