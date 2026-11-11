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
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"
#include "H5Apublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"
#include "H5Ppublic.h"

static void fuzz_H5Gget_info(hid_t loc_id) {
    H5G_info_t ginfo;
    if (H5Gget_info(loc_id, &ginfo) < 0) {
        fprintf(stderr, "H5Gget_info failed\n");
    }
}

static void fuzz_H5Aread(hid_t attr_id) {
    hid_t type_id = H5T_NATIVE_INT;
    int buf;
    if (H5Aread(attr_id, type_id, &buf) < 0) {
        fprintf(stderr, "H5Aread failed\n");
    }
}

static void fuzz_H5Fget_info2(hid_t obj_id) {
    H5F_info2_t file_info;
    if (H5Fget_info2(obj_id, &file_info) < 0) {
        fprintf(stderr, "H5Fget_info2 failed\n");
    }
}

static void fuzz_H5Aget_space(hid_t attr_id) {
    hid_t space_id = H5Aget_space(attr_id);
    if (space_id < 0) {
        fprintf(stderr, "H5Aget_space failed\n");
    } else {
        H5Sclose(space_id);
    }
}

static void fuzz_H5Dread(hid_t dset_id) {
    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;
    int buf;
    if (H5Dread(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, &buf) < 0) {
        fprintf(stderr, "H5Dread failed\n");
    }
}

static void fuzz_H5Dwrite(hid_t dset_id) {
    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;
    int buf = 42;
    if (H5Dwrite(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, &buf) < 0) {
        fprintf(stderr, "H5Dwrite failed\n");
    }
}

int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    hid_t id;
    memcpy(&id, Data, sizeof(hid_t));

    fuzz_H5Gget_info(id);
    fuzz_H5Aread(id);
    fuzz_H5Fget_info2(id);
    fuzz_H5Aget_space(id);
    fuzz_H5Dread(id);
    fuzz_H5Dwrite(id);

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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    