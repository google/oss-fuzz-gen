// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fget_access_plist at H5F.c:152:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fset_libver_bounds at H5F.c:2404:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fset_libver_bounds at H5F.c:2404:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
    }
    return file_id;
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    hid_t fapl_id = H5Fget_access_plist(file_id);
    if (fapl_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    H5F_libver_t low = (H5F_libver_t)(Data[0] % H5F_LIBVER_NBOUNDS);
    H5F_libver_t high = (H5F_libver_t)(Data[0] % H5F_LIBVER_NBOUNDS);

    herr_t status = H5Fset_libver_bounds(file_id, low, high);
    if (status < 0) {
        H5Pclose(fapl_id);
        H5Fclose(file_id);
        return 0;
    }

    char group_name[256];
    snprintf(group_name, sizeof(group_name), "group_%zu", (size_t)Data[0]);

    hid_t group_id = H5Gcreate2(file_id, group_name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Pclose(fapl_id);
        H5Fclose(file_id);
        return 0;
    }

    status = H5Gclose(group_id);
    if (status < 0) {
        H5Pclose(fapl_id);
        H5Fclose(file_id);
        return 0;
    }

    low = (H5F_libver_t)(Data[0] % H5F_LIBVER_NBOUNDS);
    high = (H5F_libver_t)(Data[0] % H5F_LIBVER_NBOUNDS);

    status = H5Fset_libver_bounds(file_id, low, high);
    if (status < 0) {
        H5Pclose(fapl_id);
        H5Fclose(file_id);
        return 0;
    }

    H5Pclose(fapl_id);
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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    