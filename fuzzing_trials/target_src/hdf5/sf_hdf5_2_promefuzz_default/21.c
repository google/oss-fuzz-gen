// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aget_space at H5A.c:1084:1 in H5Apublic.h
// H5Aget_info at H5A.c:1405:1 in H5Apublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aget_type at H5A.c:1128:1 in H5Apublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Apublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 10 + sizeof(H5A_info_t)) {
        return 0;
    }

    write_dummy_file();

    // Prepare inputs for H5Awrite
    hid_t attr_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    hid_t type_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    const void *buf = Data;

    // Call H5Awrite
    herr_t write_status = H5Awrite(attr_id, type_id, buf);

    // Prepare inputs for H5Aget_space
    hid_t space_id = H5Aget_space(attr_id);
    if (space_id >= 0) {
        H5Sclose(space_id);
    }

    // Prepare inputs for H5Aget_info
    H5A_info_t ainfo;
    herr_t info_status = H5Aget_info(attr_id, &ainfo);

    // Prepare inputs for H5Dcreate2
    hid_t loc_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    const char *name = (const char *)Data; Data += sizeof(hid_t);
    hid_t space_id2 = *(const hid_t *)Data; Data += sizeof(hid_t);
    hid_t lcpl_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    hid_t dcpl_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    hid_t dapl_id = *(const hid_t *)Data; Data += sizeof(hid_t);

    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id2, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Prepare inputs for H5Aopen_by_name
    const char *obj_name = (const char *)Data; Data += sizeof(hid_t);
    const char *attr_name = (const char *)Data; Data += sizeof(hid_t);
    hid_t aapl_id = *(const hid_t *)Data; Data += sizeof(hid_t);
    hid_t lapl_id = *(const hid_t *)Data; Data += sizeof(hid_t);

    hid_t attr_open_id = H5Aopen_by_name(loc_id, obj_name, attr_name, aapl_id, lapl_id);
    if (attr_open_id >= 0) {
        H5Aclose(attr_open_id);
    }

    // Prepare inputs for H5Aget_type
    hid_t type_id2 = H5Aget_type(attr_id);
    if (type_id2 >= 0) {
        H5Tclose(type_id2);
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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    