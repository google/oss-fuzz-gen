// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <H5Gpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>

static hid_t create_dummy_group() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return -1;
    
    hid_t group_id = H5Gcreate2(file_id, "/dummy_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    H5Fclose(file_id);
    
    return group_id;
}

static void fuzz_H5Grefresh(hid_t group_id) {
    H5Grefresh(group_id);
}

static void fuzz_H5Gget_info_by_idx(hid_t group_id) {
    H5G_info_t ginfo;
    H5Gget_info_by_idx(group_id, ".", H5_INDEX_NAME, H5_ITER_INC, 0, &ginfo, H5P_DEFAULT);
}

static void fuzz_H5Gget_info_by_name(hid_t group_id) {
    H5G_info_t ginfo;
    H5Gget_info_by_name(group_id, ".", &ginfo, H5P_DEFAULT);
}

static void fuzz_H5Gget_info(hid_t group_id) {
    H5G_info_t ginfo;
    H5Gget_info(group_id, &ginfo);
}

static void fuzz_H5Gflush(hid_t group_id) {
    H5Gflush(group_id);
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    hid_t group_id = create_dummy_group();
    if (group_id < 0) return 0;

    if (Size > 0) {
        uint8_t choice = Data[0] % 5;
        switch (choice) {
            case 0:
                fuzz_H5Grefresh(group_id);
                break;
            case 1:
                fuzz_H5Gget_info_by_idx(group_id);
                break;
            case 2:
                fuzz_H5Gget_info_by_name(group_id);
                break;
            case 3:
                fuzz_H5Gget_info(group_id);
                break;
            case 4:
                fuzz_H5Gflush(group_id);
                break;
        }
    }

    H5Gclose(group_id);
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
    