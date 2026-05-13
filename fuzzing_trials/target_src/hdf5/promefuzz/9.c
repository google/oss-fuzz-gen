// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Adelete at H5A.c:2008:1 in H5Apublic.h
// H5Adelete at H5A.c:2008:1 in H5Apublic.h
// H5Aopen_by_idx at H5A.c:792:1 in H5Apublic.h
// H5Aget_name at H5A.c:1228:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_by_idx at H5A.c:792:1 in H5Apublic.h
// H5Aget_name at H5A.c:1228:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Adelete at H5A.c:2008:1 in H5Apublic.h
// H5Aopen_by_idx at H5A.c:792:1 in H5Apublic.h
// H5Aget_name at H5A.c:1228:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Adelete at H5A.c:2008:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Apublic.h>
#include <H5Ppublic.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("HDF5 dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t dset_id = H5Dopen2(file_id, "dummy_dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    H5Adelete(dset_id, "dummy_attribute");

    H5Adelete(dset_id, "dummy_attribute");

    hid_t attr_id = H5Aopen_by_idx(dset_id, ".", H5_INDEX_NAME, H5_ITER_INC, 0, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        char name_buf[256];
        H5Aget_name(attr_id, sizeof(name_buf), name_buf);
        H5Aclose(attr_id);
    }

    attr_id = H5Aopen_by_idx(dset_id, ".", H5_INDEX_NAME, H5_ITER_INC, 1, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        char name_buf[256];
        H5Aget_name(attr_id, sizeof(name_buf), name_buf);
        H5Aclose(attr_id);
    }

    H5Adelete(dset_id, "dummy_attribute");

    attr_id = H5Aopen_by_idx(dset_id, ".", H5_INDEX_NAME, H5_ITER_INC, 2, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id >= 0) {
        char name_buf[256];
        H5Aget_name(attr_id, sizeof(name_buf), name_buf);
        H5Aclose(attr_id);
    }

    H5Adelete(dset_id, "dummy_attribute");

    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    