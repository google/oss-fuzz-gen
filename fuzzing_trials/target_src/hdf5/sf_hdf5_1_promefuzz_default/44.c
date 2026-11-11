// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
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
#include <hdf5.h>

#define DUMMY_FILE "./dummy_file"

static void create_dummy_file() {
    hid_t file_id = H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
}

static hid_t create_group(hid_t loc_id, const char *name) {
    return H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
}

static void cleanup(hid_t id) {
    if (id >= 0) {
        H5Gclose(id);
    }
}

int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    create_dummy_file();

    hid_t file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%zu", Size);

    hid_t group_id = create_group(file_id, group_name);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    H5G_info_t ginfo;
    H5Gget_info(group_id, &ginfo);

    H5Gflush(group_id);
    H5Grefresh(group_id);

    if (Size > 0) {
        H5Gget_info_by_name(file_id, group_name, &ginfo, H5P_DEFAULT);
        H5Gget_info_by_idx(file_id, ".", H5_INDEX_NAME, H5_ITER_INC, 0, &ginfo, H5P_DEFAULT);
    }

    cleanup(group_id);
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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    