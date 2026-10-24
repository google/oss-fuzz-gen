// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Aread at H5A.c:1014:1 in H5Apublic.h
// H5Fget_info2 at H5F.c:2055:1 in H5Fpublic.h
// H5Aget_space at H5A.c:1084:1 in H5Apublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Fpublic.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>
#include <H5Apublic.h>
#include <H5Spublic.h>
#include <H5Ppublic.h>

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    H5Gget_info(loc_id, &ginfo);
}

static void fuzz_H5Aread(hid_t attr_id, hid_t type_id) {
    char buf[1024];
    H5Aread(attr_id, type_id, buf);
}

static void fuzz_H5Fget_info2(hid_t obj_id) {
    H5F_info2_t finfo;
    H5Fget_info2(obj_id, &finfo);
}

static void fuzz_H5Aget_space(hid_t attr_id) {
    hid_t space_id = H5Aget_space(attr_id);
    if (space_id >= 0) {
        H5Sclose(space_id);
    }
}

static void fuzz_H5Dread(hid_t dset_id, hid_t mem_type_id) {
    char buf[1024];
    H5Dread(dset_id, mem_type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);
}

static void fuzz_H5Dwrite(hid_t dset_id, hid_t mem_type_id) {
    char buf[1024] = {0};
    H5Dwrite(dset_id, mem_type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 4) return 0;

    hid_t loc_id = ((hid_t *)Data)[0];
    hid_t attr_id = ((hid_t *)Data)[1];
    hid_t type_id = ((hid_t *)Data)[2];
    hid_t dset_id = ((hid_t *)Data)[3];

    fuzz_H5Gget_info(loc_id);
    fuzz_H5Aread(attr_id, type_id);
    fuzz_H5Fget_info2(loc_id);
    fuzz_H5Aget_space(attr_id);
    fuzz_H5Dread(dset_id, type_id);
    fuzz_H5Dwrite(dset_id, type_id);

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
    