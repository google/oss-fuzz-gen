// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dwrite_chunk at H5D.c:1491:1 in H5Dpublic.h
// H5Fflush at H5F.c:957:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Dget_chunk_storage_size at H5D.c:2218:1 in H5Dpublic.h
// H5Dread_chunk2 at H5D.c:1181:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Fpublic.h>
#include <H5Dpublic.h>
#include <H5Ppublic.h>
#include <H5Tpublic.h>
#include <H5Spublic.h>

static void prepare_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        // Write necessary data to the dummy file
        // This is a placeholder, adjust according to actual requirements
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    // Prepare environment
    prepare_dummy_file();

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t space_id = H5Screate_simple(1, (const hsize_t[]){10}, NULL);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = H5Dcreate2(file_id, "dset", H5T_NATIVE_INT, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hsize_t offset[1] = {0};
    uint32_t filters = 0;
    size_t buf_size = 10 * sizeof(int);
    int data[10] = {0};

    // Invoke H5Dwrite_chunk
    H5Dwrite_chunk(dset_id, H5P_DEFAULT, filters, offset, buf_size, data);

    // Invoke H5Fflush
    H5Fflush(file_id, H5F_SCOPE_LOCAL);

    // Close and reopen dataset
    H5Dclose(dset_id);
    dset_id = H5Dopen2(file_id, "dset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Read data
    H5Dread(dset_id, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);

    // Get chunk storage size
    hsize_t chunk_bytes = 0;
    H5Dget_chunk_storage_size(dset_id, offset, &chunk_bytes);

    // Read chunk multiple times
    for (int i = 0; i < 4; i++) {
        H5Dread_chunk2(dset_id, H5P_DEFAULT, offset, &filters, data, &buf_size);
    }

    // Cleanup
    H5Dclose(dset_id);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    