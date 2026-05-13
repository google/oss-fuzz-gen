#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Ppublic.h" // Include this header for H5P_DEFAULT

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare a filename for HDF5 file creation
    const char *filename = "./dummy_file";

    // Initialize variables for H5Fcreate
    unsigned flags = H5F_ACC_TRUNC;
    hid_t fcpl_id = H5P_DEFAULT;
    hid_t fapl_id = H5P_DEFAULT;

    // Create an HDF5 file
    hid_t file_id = H5Fcreate(filename, flags, fcpl_id, fapl_id);
    if (file_id < 0) {
        return 0;
    }

    // Prepare arrays for page buffering statistics
    unsigned accesses[2] = {0, 0};
    unsigned hits[2] = {0, 0};
    unsigned misses[2] = {0, 0};
    unsigned evictions[2] = {0, 0};
    unsigned bypasses[2] = {0, 0};

    // Reset page buffering stats
    herr_t status = H5Freset_page_buffering_stats(file_id);
    if (status < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get page buffering stats
    status = H5Fget_page_buffering_stats(file_id, accesses, hits, misses, evictions, bypasses);
    if (status < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Reset page buffering stats again
    status = H5Freset_page_buffering_stats(file_id);
    if (status < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Get page buffering stats again
    status = H5Fget_page_buffering_stats(file_id, accesses, hits, misses, evictions, bypasses);
    if (status < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Close the HDF5 file
    status = H5Fclose(file_id);
    if (status < 0) {
        return 0;
    }

    // Attempt to close the file again (should fail as it is already closed)
    status = H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
