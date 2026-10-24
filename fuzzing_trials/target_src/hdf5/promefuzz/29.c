// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_chunk_index_type at H5D.c:2177:1 in H5Dpublic.h
// H5Dget_num_chunks at H5D.c:2268:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dget_num_chunks at H5D.c:2268:1 in H5Dpublic.h
// H5Dget_chunk_info at H5D.c:2317:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"
#include "H5Spublic.h"
#include "H5Tpublic.h"
#include "H5Ppublic.h"

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        const char *data = "dummy data";
        fwrite(data, 1, strlen(data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file("./dummy_file");

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hid_t space_id = H5Screate(H5S_SCALAR);
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = H5Dcreate2(file_id, "dataset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    herr_t status = H5Dclose(dset_id);
    if (status < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    H5D_chunk_index_t idx_type;
    status = H5Dget_chunk_index_type(dset_id, &idx_type);

    hsize_t nchunks;
    status = H5Dget_num_chunks(dset_id, H5S_ALL, &nchunks);

    int data = 42;
    status = H5Dwrite(dset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, &data);

    status = H5Dget_num_chunks(dset_id, H5S_ALL, &nchunks);

    hsize_t offset[1];
    unsigned filter_mask;
    haddr_t addr;
    hsize_t size;
    status = H5Dget_chunk_info(dset_id, H5S_ALL, 0, offset, &filter_mask, &addr, &size);

    H5Dclose(dset_id);
    H5Tclose(type_id);
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    