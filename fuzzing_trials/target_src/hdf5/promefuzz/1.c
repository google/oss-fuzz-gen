// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Fget_intent at H5F.c:1540:1 in H5Fpublic.h
// H5Fget_fileno at H5F.c:1579:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_vfd_handle at H5F.c:422:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <hdf5.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy content", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    hid_t file_id, dset_id, fapl_id, fcpl_id;
    herr_t status;
    unsigned intent;
    unsigned long fileno;
    void *file_handle;
    hssize_t free_space;

    // Write dummy data to file
    write_dummy_file();

    // Open the HDF5 file
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Get file access plist
    fapl_id = H5Fget_access_plist(file_id);
    if (fapl_id < 0) goto close_file;

    // Open a dataset
    dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) goto close_fapl;

    // Get file create plist
    fcpl_id = H5Fget_create_plist(file_id);
    if (fcpl_id < 0) goto close_dset;

    // Get file access plist again
    fapl_id = H5Fget_access_plist(file_id);
    if (fapl_id < 0) goto close_fcpl;

    // Get file intent
    status = H5Fget_intent(file_id, &intent);
    if (status < 0) goto close_fcpl;

    // Get file number
    status = H5Fget_fileno(file_id, &fileno);
    if (status < 0) goto close_fcpl;

    // Get free space in file
    free_space = H5Fget_freespace(file_id);
    if (free_space < 0) goto close_fcpl;

    // Get VFD handle
    status = H5Fget_vfd_handle(file_id, H5P_DEFAULT, &file_handle);
    if (status < 0) goto close_fcpl;

close_fcpl:
    H5Pclose(fcpl_id);
close_dset:
    H5Dclose(dset_id);
close_fapl:
    H5Pclose(fapl_id);
close_file:
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
    