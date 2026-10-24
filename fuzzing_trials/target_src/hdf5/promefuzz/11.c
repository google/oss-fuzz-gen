// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclear_elink_file_cache at H5F.c:2194:1 in H5Fpublic.h
// H5Fflush at H5F.c:957:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fis_accessible at H5F.c:464:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Freopen at H5F.c:1440:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "H5Fpublic.h"
#include "H5Ppublic.h"

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file() {
    FILE *fp = fopen(DUMMY_FILE, "w");
    if (fp) {
        fprintf(fp, "This is a dummy HDF5 file.");
        fclose(fp);
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare the environment
    write_dummy_file();

    hid_t file_id = -1;
    hid_t new_file_id = -1;
    hid_t fapl_id = H5P_DEFAULT;
    herr_t status;
    htri_t accessible;

    // H5Fopen
    file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    // H5Fclear_elink_file_cache
    status = H5Fclear_elink_file_cache(file_id);
    if (status < 0) goto cleanup;

    // H5Fflush
    status = H5Fflush(file_id, H5F_SCOPE_LOCAL);
    if (status < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

    // H5Fis_accessible
    accessible = H5Fis_accessible(DUMMY_FILE, fapl_id);
    if (accessible < 0) goto cleanup;

    // H5Fopen
    file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, fapl_id);
    if (file_id < 0) goto cleanup;

    // H5Fget_access_plist
    hid_t plist_id = H5Fget_access_plist(file_id);
    if (plist_id < 0) goto cleanup;

    // H5Freopen
    new_file_id = H5Freopen(file_id);
    if (new_file_id < 0) goto cleanup;

    // H5Fget_access_plist
    hid_t new_plist_id = H5Fget_access_plist(new_file_id);
    if (new_plist_id < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(new_file_id);
    if (status < 0) goto cleanup;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) goto cleanup;

    // Cleanup
cleanup:
    if (file_id >= 0) H5Fclose(file_id);
    if (new_file_id >= 0) H5Fclose(new_file_id);
    if (plist_id >= 0) H5Pclose(plist_id);
    if (new_plist_id >= 0) H5Pclose(new_plist_id);
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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    