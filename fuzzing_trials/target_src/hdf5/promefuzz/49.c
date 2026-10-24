// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate_async at H5F.c:673:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_space_async at H5D.c:625:1 in H5Dpublic.h
// H5Dopen_async at H5D.c:418:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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
#include <H5Spublic.h>
#include <H5Ppublic.h>
#include <H5Tpublic.h>
#include <H5ESpublic.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate_async("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT, H5ES_NONE);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
    }
    return file_id;
}

static hid_t create_dummy_dataset(hid_t file_id) {
    hsize_t dims[2] = {10, 10};
    hid_t space_id = H5Screate_simple(2, dims, NULL);
    if (space_id < 0) {
        fprintf(stderr, "Failed to create dataspace\n");
        return -1;
    }
    hid_t dset_id = H5Dcreate_async(file_id, "dummy_dataset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT, H5ES_NONE);
    H5Sclose(space_id);
    if (dset_id < 0) {
        fprintf(stderr, "Failed to create dummy dataset\n");
    }
    return dset_id;
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    hid_t dset_id = create_dummy_dataset(file_id);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Dget_space_async
    hid_t space_id = H5Dget_space_async(dset_id, H5ES_NONE);
    if (space_id >= 0) {
        H5Sclose(space_id);
    }

    // Fuzz H5Dread_async
    int buf[100];
    herr_t status = H5Dread_async(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf, H5ES_NONE);
    if (status < 0) {
        fprintf(stderr, "Failed to read dataset asynchronously\n");
    }

    // Fuzz H5Dopen_async
    hid_t dset_id2 = H5Dopen_async(file_id, "dummy_dataset", H5P_DEFAULT, H5ES_NONE);
    if (dset_id2 >= 0) {
        H5Dclose(dset_id2);
    }

    // Fuzz H5Acreate_async
    hid_t attr_id = H5Acreate_async(dset_id, "dummy_attr", H5T_NATIVE_INT, H5S_ALL, H5P_DEFAULT, H5P_DEFAULT, H5ES_NONE);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    