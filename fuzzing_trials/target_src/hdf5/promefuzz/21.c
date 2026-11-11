// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_info1 at H5Fdeprec.c:86:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Fset_latest_format at H5Fdeprec.c:206:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Fget_info1 at H5Fdeprec.c:86:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_info1 at H5Fdeprec.c:86:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_create_plist at H5F.c:106:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Ppublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file != NULL) {
        fprintf(file, "This is a dummy file for HDF5 fuzzing.\n");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    hid_t file_id, plist_id;
    H5F_info1_t file_info;
    herr_t status;

    // H5Fcreate
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // H5Fget_info1
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;
    status = H5Fget_info1(file_id, &file_info);
    if (status < 0) return 0;

    // H5Fget_create_plist
    plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;

    // H5Fset_latest_format
    status = H5Fset_latest_format(file_id, true);
    if (status < 0) return 0;
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // H5Fcreate
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // H5Fget_access_plist
    plist_id = H5Fget_access_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;

    // H5Fget_info1
    status = H5Fget_info1(file_id, &file_info);
    if (status < 0) return 0;

    // H5Fget_create_plist
    plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // H5Fopen
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // H5Fget_info1
    status = H5Fget_info1(file_id, &file_info);
    if (status < 0) return 0;

    // H5Fget_create_plist
    plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // H5Fcreate
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // H5Fget_create_plist
    plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;
    status = H5Fclose(file_id);
    if (status < 0) return 0;

    // H5Fopen
    file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // H5Fget_create_plist
    plist_id = H5Fget_create_plist(file_id);
    if (plist_id < 0) return 0;
    status = H5Pclose(plist_id);
    if (status < 0) return 0;
    status = H5Fclose(file_id);
    if (status < 0) return 0;

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    