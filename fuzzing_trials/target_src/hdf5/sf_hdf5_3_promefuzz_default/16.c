// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Apublic.h"
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h" // Include this header for H5P_DEFAULT

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data for IDs

    // Prepare environment
    hid_t loc_id = (hid_t)Data[0];
    const char *obj_name = "dummy_object";
    const char *attr_name = "dummy_attribute";
    hid_t aapl_id = (hid_t)Data[1];
    hid_t lapl_id = (hid_t)Data[2];
    hid_t type_id = (hid_t)Data[3];
    hid_t space_id = (hid_t)Data[3];
    hid_t acpl_id = H5P_DEFAULT;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;

    write_dummy_file();

    // Target function calls

    // H5Aopen_by_name
    hid_t attr_id = H5Aopen_by_name(loc_id, obj_name, attr_name, aapl_id, lapl_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // H5Acreate2
    attr_id = H5Acreate2(loc_id, attr_name, type_id, space_id, acpl_id, aapl_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // H5Aopen_name
    attr_id = H5Aopen_name(loc_id, attr_name);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // H5Gcreate2
    hid_t group_id = H5Gcreate2(loc_id, obj_name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // H5Dcreate2
    hid_t dataset_id = H5Dcreate2(loc_id, obj_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    