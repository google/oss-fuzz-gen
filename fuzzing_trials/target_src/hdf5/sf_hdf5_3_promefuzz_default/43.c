// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Gget_linkval at H5Gdeprec.c:633:1 in H5Gpublic.h
// H5Gmove2 at H5Gdeprec.c:512:1 in H5Gpublic.h
// H5Gmove at H5Gdeprec.c:469:1 in H5Gpublic.h
// H5Glink at H5Gdeprec.c:294:1 in H5Gpublic.h
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
#include <string.h>
#include "H5Gpublic.h"
#include "H5Ppublic.h"
#include "H5Fpublic.h"

static void fuzz_H5Glink2(hid_t cur_loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *cur_name = (const char *)Data;
    const char *new_name = (const char *)(Data + 1);
    H5G_link_t type = (H5G_link_t)(Data[0] % 2); // Randomly choose between hard and soft link

    H5Glink2(cur_loc_id, cur_name, type, cur_loc_id, new_name);
}

static void fuzz_H5Gget_linkval(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *name = (const char *)Data;
    size_t buf_size = 256;
    char buf[256];

    H5Gget_linkval(loc_id, name, buf_size, buf);
}

static void fuzz_H5Gmove2(hid_t src_loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *src_name = (const char *)Data;
    const char *dst_name = (const char *)(Data + 1);

    H5Gmove2(src_loc_id, src_name, src_loc_id, dst_name);
}

static void fuzz_H5Gmove(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *src_name = (const char *)Data;
    const char *dst_name = (const char *)(Data + 1);

    H5Gmove(loc_id, src_name, dst_name);
}

static void fuzz_H5Glink(hid_t cur_loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *cur_name = (const char *)Data;
    const char *new_name = (const char *)(Data + 1);
    H5G_link_t type = (H5G_link_t)(Data[0] % 2); // Randomly choose between hard and soft link

    H5Glink(cur_loc_id, type, cur_name, new_name);
}

static void fuzz_H5Gcreate2(hid_t loc_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *name = (const char *)Data;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;

    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    fuzz_H5Glink2(file_id, Data, Size);
    fuzz_H5Gget_linkval(file_id, Data, Size);
    fuzz_H5Gmove2(file_id, Data, Size);
    fuzz_H5Gmove(file_id, Data, Size);
    fuzz_H5Glink(file_id, Data, Size);
    fuzz_H5Gcreate2(file_id, Data, Size);

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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    