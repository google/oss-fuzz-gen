// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>
#include "H5Gpublic.h"

static hid_t create_test_group() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return H5I_INVALID_HID;

    hid_t group_id = H5Gcreate2(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Fclose(file_id);
    return group_id;
}

static void test_H5Grefresh(hid_t group_id) {
    if (H5Grefresh(group_id) < 0) {
        fprintf(stderr, "H5Grefresh failed\n");
    }
}

static void test_H5Gclose(hid_t group_id) {
    if (H5Gclose(group_id) < 0) {
        fprintf(stderr, "H5Gclose failed\n");
    }
}

static void test_H5Gget_info_by_name(hid_t loc_id) {
    H5G_info_t ginfo;
    if (H5Gget_info_by_name(loc_id, "test_group", &ginfo, H5P_DEFAULT) < 0) {
        fprintf(stderr, "H5Gget_info_by_name failed\n");
    }
}

static void test_H5Gget_info(hid_t group_id) {
    H5G_info_t ginfo;
    if (H5Gget_info(group_id, &ginfo) < 0) {
        fprintf(stderr, "H5Gget_info failed\n");
    }
}

static void test_H5Gflush(hid_t group_id) {
    if (H5Gflush(group_id) < 0) {
        fprintf(stderr, "H5Gflush failed\n");
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    // Create a test group
    hid_t group_id = create_test_group();
    if (group_id == H5I_INVALID_HID) {
        return 0;
    }

    // Call the target functions with the group_id
    test_H5Grefresh(group_id);
    test_H5Gget_info_by_name(group_id);
    test_H5Gget_info(group_id);
    test_H5Gflush(group_id);

    // Close the group
    test_H5Gclose(group_id);

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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    