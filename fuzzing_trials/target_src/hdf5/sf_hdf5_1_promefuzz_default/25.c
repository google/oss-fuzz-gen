// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gcreate_anon at H5G.c:314:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_idx at H5G.c:795:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Gpublic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fprintf(file, "Dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 3) {
        return 0;
    }

    write_dummy_file();

    hid_t loc_id = *((hid_t *)Data);
    hid_t gcpl_id = *((hid_t *)(Data + sizeof(hid_t)));
    hid_t gapl_id = *((hid_t *)(Data + 2 * sizeof(hid_t)));

    // Fuzz H5Gcreate_anon
    hid_t group_id = H5Gcreate_anon(loc_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Fuzz H5Gget_info_by_idx
    if (Size >= sizeof(hid_t) * 3 + sizeof(hsize_t) + sizeof(H5_index_t) + sizeof(H5_iter_order_t)) {
        const char *group_name = ".";
        H5_index_t idx_type = *((H5_index_t *)(Data + 3 * sizeof(hid_t)));
        H5_iter_order_t order = *((H5_iter_order_t *)(Data + 3 * sizeof(hid_t) + sizeof(H5_index_t)));
        hsize_t n = *((hsize_t *)(Data + 3 * sizeof(hid_t) + sizeof(H5_index_t) + sizeof(H5_iter_order_t)));
        H5G_info_t ginfo;

        herr_t status = H5Gget_info_by_idx(loc_id, group_name, idx_type, order, n, &ginfo, gapl_id);
    }

    // Fuzz H5Gopen2
    if (Size >= sizeof(hid_t) * 3 + 1) {
        const char *name = (const char *)(Data + 3 * sizeof(hid_t));
        hid_t opened_group_id = H5Gopen2(loc_id, name, gapl_id);
        if (opened_group_id >= 0) {
            H5Gclose(opened_group_id);
        }
    }

    // Fuzz H5Gget_info_by_name
    if (Size >= sizeof(hid_t) * 3 + 1) {
        const char *name = (const char *)(Data + 3 * sizeof(hid_t));
        H5G_info_t ginfo;
        herr_t status = H5Gget_info_by_name(loc_id, name, &ginfo, gapl_id);
    }

    // Fuzz H5Gget_info
    if (Size >= sizeof(hid_t)) {
        H5G_info_t ginfo;
        herr_t status = H5Gget_info(loc_id, &ginfo);
    }

    // Fuzz H5Gflush
    if (Size >= sizeof(hid_t)) {
        herr_t status = H5Gflush(loc_id);
    }

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
    