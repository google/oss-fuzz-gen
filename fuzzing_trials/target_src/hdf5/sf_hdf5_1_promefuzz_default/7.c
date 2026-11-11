// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
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
#include <hdf5.h>
#include <H5Gpublic.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file.\n");
    }
    return file_id;
}

static hid_t create_group(hid_t file_id, const char *group_name) {
    if (file_id < 0) {
        fprintf(stderr, "Invalid file ID.\n");
        return -1;
    }
    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        fprintf(stderr, "Failed to create group: %s\n", group_name);
    }
    return group_id;
}

static void fuzz_H5Grefresh(hid_t group_id) {
    if (group_id < 0) return;
    herr_t status = H5Grefresh(group_id);
    if (status < 0) {
        fprintf(stderr, "H5Grefresh failed.\n");
    }
}

static void fuzz_H5Gclose(hid_t group_id) {
    if (group_id < 0) return;
    herr_t status = H5Gclose(group_id);
    if (status < 0) {
        fprintf(stderr, "H5Gclose failed.\n");
    }
}

static void fuzz_H5Gget_info_by_name(hid_t loc_id, const char *name) {
    if (loc_id < 0) return;
    H5G_info_t ginfo;
    herr_t status = H5Gget_info_by_name(loc_id, name, &ginfo, H5P_DEFAULT);
    if (status < 0) {
        fprintf(stderr, "H5Gget_info_by_name failed.\n");
    }
}

static void fuzz_H5Gget_info(hid_t loc_id) {
    if (loc_id < 0) return;
    H5G_info_t ginfo;
    herr_t status = H5Gget_info(loc_id, &ginfo);
    if (status < 0) {
        fprintf(stderr, "H5Gget_info failed.\n");
    }
}

static void fuzz_H5Gflush(hid_t group_id) {
    if (group_id < 0) return;
    herr_t status = H5Gflush(group_id);
    if (status < 0) {
        fprintf(stderr, "H5Gflush failed.\n");
    }
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least one byte for group name

    // Prepare environment
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    char group_name[Size + 1];
    memcpy(group_name, Data, Size);
    group_name[Size] = '\0'; // Null-terminate the group name

    // Create a group
    hid_t group_id = create_group(file_id, group_name);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz the target functions
    fuzz_H5Grefresh(group_id);
    fuzz_H5Gget_info_by_name(file_id, group_name);
    fuzz_H5Gget_info(group_id);
    fuzz_H5Gflush(group_id);

    // Cleanup
    fuzz_H5Gclose(group_id);
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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    