// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Aopen_async at H5A.c:556:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dcreate_async at H5D.c:206:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Acreate_by_name_async at H5A.c:393:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate_async at H5A.c:247:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aexists_by_name_async at H5A.c:2502:1 in H5Apublic.h
// H5Aopen_by_name_async at H5A.c:683:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <H5Dpublic.h>
#include <H5Apublic.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy data", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Not enough data

    write_dummy_file();

    const char *app_file = "dummy_file";
    const char *app_func = "dummy_func";
    unsigned app_line = 42;

    // Assuming Data contains a valid string for names
    char obj_name[256], attr_name[256], dataset_name[256];
    snprintf(obj_name, sizeof(obj_name), "obj_%.*s", (int)Size, Data);
    snprintf(attr_name, sizeof(attr_name), "attr_%.*s", (int)Size, Data);
    snprintf(dataset_name, sizeof(dataset_name), "dset_%.*s", (int)Size, Data);

    hid_t obj_id = 1; // Dummy object ID
    hid_t loc_id = 1; // Dummy location ID
    hid_t type_id = 1; // Dummy type ID
    hid_t space_id = 1; // Dummy space ID
    hid_t aapl_id = 1; // Dummy attribute access property list ID
    hid_t es_id = 1; // Dummy event set ID
    hid_t acpl_id = 1; // Dummy attribute creation property list ID
    hid_t lcpl_id = 1; // Dummy link creation property list ID
    hid_t dcpl_id = 1; // Dummy dataset creation property list ID
    hid_t dapl_id = 1; // Dummy dataset access property list ID
    hid_t lapl_id = 1; // Dummy link access property list ID

    // Fuzz H5Aopen_async
    hid_t attr_id = H5Aopen_async(obj_id, attr_name, aapl_id, es_id);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Fuzz H5Dcreate_async
    hid_t dset_id = H5Dcreate_async(loc_id, dataset_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id, es_id);
    if (dset_id >= 0) {
        H5Dclose(dset_id);
    }

    // Fuzz H5Acreate_by_name_async
    hid_t attr_create_id = H5Acreate_by_name_async(loc_id, obj_name, attr_name, type_id, space_id, acpl_id, aapl_id, lapl_id, es_id);
    if (attr_create_id >= 0) {
        H5Aclose(attr_create_id);
    }

    // Fuzz H5Acreate_async
    hid_t attr_create_async_id = H5Acreate_async(loc_id, attr_name, type_id, space_id, acpl_id, aapl_id, es_id);
    if (attr_create_async_id >= 0) {
        H5Aclose(attr_create_async_id);
    }

    // Fuzz H5Aexists_by_name_async
    bool exists;
    herr_t exists_status = H5Aexists_by_name_async(loc_id, obj_name, attr_name, &exists, lapl_id, es_id);
    if (exists_status >= 0) {
        // Use the exists value if needed
    }

    // Fuzz H5Aopen_by_name_async
    hid_t attr_open_id = H5Aopen_by_name_async(loc_id, obj_name, attr_name, aapl_id, lapl_id, es_id);
    if (attr_open_id >= 0) {
        H5Aclose(attr_open_id);
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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    