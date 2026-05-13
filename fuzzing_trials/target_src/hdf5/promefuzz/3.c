// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_num_chunks at H5D.c:2268:1 in H5Dpublic.h
// H5Dget_chunk_info at H5D.c:2317:1 in H5Dpublic.h
// H5Dget_chunk_info_by_coord at H5D.c:2386:1 in H5Dpublic.h
// H5Dchunk_iter at H5D.c:2437:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fdelete at H5F.c:1117:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Ppublic.h>
#include <H5Spublic.h>

static herr_t chunk_iter_cb(const hsize_t *offset, unsigned filter_mask, haddr_t addr, hsize_t size, void *op_data) {
    // Dummy callback function for H5Dchunk_iter
    return 0;
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;  // Ensure there's enough data for meaningful operations

    // Create a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the HDF5 file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Open dataset
    hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get number of chunks
    hsize_t nchunks;
    H5Dget_num_chunks(dset_id, H5S_ALL, &nchunks);

    // Get chunk info
    hsize_t offset[1];
    unsigned filter_mask;
    haddr_t addr;
    hsize_t size;
    H5Dget_chunk_info(dset_id, H5S_ALL, 0, offset, &filter_mask, &addr, &size);

    // Get chunk info by coord
    H5Dget_chunk_info_by_coord(dset_id, offset, &filter_mask, &addr, &size);

    // Iterate over chunks
    H5Dchunk_iter(dset_id, H5P_DEFAULT, chunk_iter_cb, NULL);

    // Close dataset
    H5Dclose(dset_id);

    // Close file
    H5Fclose(file_id);

    // Delete the file
    H5Fdelete("./dummy_file", H5P_DEFAULT);

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

        LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    