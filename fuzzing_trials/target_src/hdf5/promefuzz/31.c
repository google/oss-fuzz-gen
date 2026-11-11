// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_space at H5D.c:597:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dvlen_get_buf_size at H5D.c:1889:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
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
#include "hdf5.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        // Write some dummy data to the file
        const char dummy_data[] = "HDF5 dummy data";
        fwrite(dummy_data, sizeof(dummy_data) - 1, 1, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Write dummy data to the file
    write_dummy_file();

    // Open the file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Open a dataset
    hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get the dataspace
    hid_t space_id = H5Dget_space(dset_id);
    if (space_id < 0) {
        H5Dclose(dset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get the datatype
    hid_t type_id = H5Dget_type(dset_id);
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Dclose(dset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get the buffer size for variable-length data
    hsize_t buf_size = 0;
    if (H5Dvlen_get_buf_size(dset_id, type_id, space_id, &buf_size) < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Dclose(dset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Allocate buffer and read data
    void *buf = malloc(buf_size);
    if (buf) {
        H5Dread(dset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, buf);
        free(buf);
    }

    // Cleanup resources
    H5Tclose(type_id);
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    