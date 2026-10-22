// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aget_space at H5A.c:1084:1 in H5Apublic.h
// H5Aget_info at H5A.c:1405:1 in H5Apublic.h
// H5Aget_type at H5A.c:1128:1 in H5Apublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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
#include <string.h>
#include <hdf5.h>

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    // Prepare environment
    hid_t file_id, space_id, attr_id, type_id, dataset_id;
    H5A_info_t ainfo;
    herr_t status;
    const char *filename = "./dummy_file";
    const char *dataset_name = "dset";
    const char *attr_name = "attr";
    write_dummy_file(filename);

    file_id = H5Fopen(filename, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create dataspace for dataset
    hsize_t dims[1] = {10};
    space_id = H5Screate_simple(1, dims, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Create a dataset
    dataset_id = H5Dcreate2(file_id, dataset_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Create an attribute
    attr_id = H5Acreate2(dataset_id, attr_name, H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Dclose(dataset_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Fuzz H5Awrite
    if (Size >= sizeof(int)) {
        status = H5Awrite(attr_id, H5T_NATIVE_INT, Data);
    }

    // Fuzz H5Aget_space
    hid_t space_copy_id = H5Aget_space(attr_id);
    if (space_copy_id >= 0) {
        H5Sclose(space_copy_id);
    }

    // Fuzz H5Aget_info
    status = H5Aget_info(attr_id, &ainfo);

    // Fuzz H5Aget_type
    type_id = H5Aget_type(attr_id);
    if (type_id >= 0) {
        H5Tclose(type_id);
    }

    // Fuzz H5Aopen_by_name
    hid_t attr_open_id = H5Aopen_by_name(file_id, dataset_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    if (attr_open_id >= 0) {
        H5Aclose(attr_open_id);
    }

    // Cleanup
    H5Aclose(attr_id);
    H5Dclose(dataset_id);
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    