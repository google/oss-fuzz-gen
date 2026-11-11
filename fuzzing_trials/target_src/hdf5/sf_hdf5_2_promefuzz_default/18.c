// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate1 at H5Adeprec.c:103:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aget_num_attrs at H5Adeprec.c:303:1 in H5Apublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Apublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize environment
    write_dummy_file();

    // Use some data from the input to create names and identifiers
    const char *attr_name = "test_attr";
    const char *dataset_name = "test_dataset";
    hid_t loc_id = Data[0];
    hid_t type_id = Data[0] + 1;
    hid_t space_id = Data[0] + 2;
    hid_t acpl_id = Data[0] + 3;
    hid_t aapl_id = Data[0] + 4;
    hid_t lcpl_id = Data[0] + 5;
    hid_t dcpl_id = Data[0] + 6;
    hid_t dapl_id = Data[0] + 7;

    // Fuzz H5Acreate2
    hid_t attr_id = H5Acreate2(loc_id, attr_name, type_id, space_id, acpl_id, aapl_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Fuzz H5Acreate1
    attr_id = H5Acreate1(loc_id, attr_name, type_id, space_id, acpl_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Fuzz H5Aopen_name
    attr_id = H5Aopen_name(loc_id, attr_name);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Fuzz H5Aget_num_attrs
    int num_attrs = H5Aget_num_attrs(loc_id);
    (void)num_attrs;  // Use the result to avoid compiler warnings

    // Fuzz H5Dcreate2
    hid_t dataset_id = H5Dcreate2(loc_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Fuzz H5Aopen_by_name
    attr_id = H5Aopen_by_name(loc_id, dataset_name, attr_name, aapl_id, dapl_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    