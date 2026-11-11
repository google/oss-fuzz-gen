// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Gget_linkval at H5Gdeprec.c:633:1 in H5Gpublic.h
// H5Gmove2 at H5Gdeprec.c:512:1 in H5Gpublic.h
// H5Gmove at H5Gdeprec.c:469:1 in H5Gpublic.h
// H5Glink at H5Gdeprec.c:294:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Gpublic.h"
#include "H5Ppublic.h"  // Include this header for H5P_DEFAULT

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "This is a dummy file for HDF5 testing.\n");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t loc_id = (hid_t)Data[0];
    const char *cur_name = "existing_object";
    const char *new_name = "new_link";
    H5G_link_t link_type = (H5G_link_t)(Data[0] % 2);

    if (H5Glink2(loc_id, cur_name, link_type, loc_id, new_name) < 0) {
        fprintf(stderr, "H5Glink2 failed\n");
    }

    char buf[1024];
    if (H5Gget_linkval(loc_id, "symbolic_link", sizeof(buf), buf) < 0) {
        fprintf(stderr, "H5Gget_linkval failed\n");
    }

    const char *src_name = "src_object";
    const char *dst_name = "dst_object";
    if (H5Gmove2(loc_id, src_name, loc_id, dst_name) < 0) {
        fprintf(stderr, "H5Gmove2 failed\n");
    }

    if (H5Gmove(loc_id, src_name, dst_name) < 0) {
        fprintf(stderr, "H5Gmove failed\n");
    }

    if (H5Glink(loc_id, link_type, cur_name, new_name) < 0) {
        fprintf(stderr, "H5Glink failed\n");
    }

    hid_t group_id = H5Gcreate2(loc_id, "new_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        fprintf(stderr, "H5Gcreate2 failed\n");
    } else {
        H5Gclose(group_id);
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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    