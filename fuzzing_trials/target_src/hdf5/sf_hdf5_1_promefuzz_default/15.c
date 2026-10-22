// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dfill at H5D.c:1758:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_info2 at H5F.c:2055:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <hdf5.h>
#include <H5Fpublic.h>
#include <H5Gpublic.h>
#include <H5Dpublic.h>

static void test_H5Dfill(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int))
        return;

    int fill_value = *((int *)Data);
    hid_t fill_type_id = H5T_NATIVE_INT;
    hid_t buf_type_id = H5T_NATIVE_INT;
    int buf[10];
    hid_t space_id = H5Screate_simple(1, (hsize_t[]){10}, NULL);

    H5Dfill(&fill_value, fill_type_id, buf, buf_type_id, space_id);

    H5Sclose(space_id);
}

static void test_H5Dcreate2(const uint8_t *Data, size_t Size) {
    if (Size < 1)
        return;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    hid_t space_id = H5Screate_simple(1, (hsize_t[]){10}, NULL);
    hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }

    H5Sclose(space_id);
    H5Fclose(file_id);
}

static void test_H5Gget_info(const uint8_t *Data, size_t Size) {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    H5G_info_t ginfo;
    H5Gget_info(file_id, &ginfo);
    H5Fclose(file_id);
}

static void test_H5Fget_info2(const uint8_t *Data, size_t Size) {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    H5F_info2_t finfo;
    H5Fget_info2(file_id, &finfo);
    H5Fclose(file_id);
}

static void test_H5Dread(const uint8_t *Data, size_t Size) {
    if (Size < 1)
        return;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    hid_t space_id = H5Screate_simple(1, (hsize_t[]){10}, NULL);
    hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    
    int buf[10];
    H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);

    H5Dclose(dset_id);
    H5Sclose(space_id);
    H5Fclose(file_id);
}

static void test_H5Dwrite(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 10)
        return;

    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    hid_t space_id = H5Screate_simple(1, (hsize_t[]){10}, NULL);
    hid_t dset_id = H5Dcreate2(file_id, "dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    
    H5Dwrite(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, Data);

    H5Dclose(dset_id);
    H5Sclose(space_id);
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    test_H5Dfill(Data, Size);
    test_H5Dcreate2(Data, Size);
    test_H5Gget_info(Data, Size);
    test_H5Fget_info2(Data, Size);
    test_H5Dread(Data, Size);
    test_H5Dwrite(Data, Size);
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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    