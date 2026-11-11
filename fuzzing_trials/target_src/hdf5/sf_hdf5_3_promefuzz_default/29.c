// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dwrite_multi at H5D.c:1419:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "H5Dpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h" // Include this header for H5P_DEFAULT

static void create_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "This is a dummy HDF5 file for fuzzing.\n");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) {
        return 0;
    }

    create_dummy_file();

    // Extract values from the input data
    size_t count = *((size_t *)Data);
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    if (count == 0 || Size < sizeof(hid_t) * (4 * count + 1)) {
        return 0;
    }

    hid_t *dset_id = (hid_t *)Data;
    Data += sizeof(hid_t) * count;
    Size -= sizeof(hid_t) * count;

    hid_t *mem_type_id = (hid_t *)Data;
    Data += sizeof(hid_t) * count;
    Size -= sizeof(hid_t) * count;

    hid_t *mem_space_id = (hid_t *)Data;
    Data += sizeof(hid_t) * count;
    Size -= sizeof(hid_t) * count;

    hid_t *file_space_id = (hid_t *)Data;
    Data += sizeof(hid_t) * count;
    Size -= sizeof(hid_t) * count;

    hid_t dxpl_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    if (Size < sizeof(void *) * count) {
        return 0;
    }

    const void **buf = (const void **)Data;

    // Fuzz H5Dwrite_multi
    herr_t status = H5Dwrite_multi(count, dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf);
    if (status < 0) {
        fprintf(stderr, "H5Dwrite_multi failed\n");
    }

    // Fuzz H5Dget_type
    for (size_t i = 0; i < count; i++) {
        hid_t type_id = H5Dget_type(dset_id[i]);
        if (type_id == H5I_INVALID_HID) {
            fprintf(stderr, "H5Dget_type failed for dataset %zu\n", i);
        } else {
            H5Tclose(type_id); // Close the datatype identifier to prevent resource leaks
        }
    }

    // Fuzz H5Dread
    for (size_t i = 0; i < count; i++) {
        void *read_buf = malloc(1024); // Allocate a buffer for reading
        if (read_buf) {
            status = H5Dread(dset_id[i], mem_type_id[i], mem_space_id[i], file_space_id[i], dxpl_id, read_buf);
            if (status < 0) {
                fprintf(stderr, "H5Dread failed for dataset %zu\n", i);
            }
            free(read_buf);
        }
    }

    // Fuzz H5Gcreate2
    hid_t group_id = H5Gcreate2(dset_id[0], "group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id == H5I_INVALID_HID) {
        fprintf(stderr, "H5Gcreate2 failed\n");
    } else {
        H5Gclose(group_id);
    }

    // Fuzz H5Dopen2
    hid_t dataset_id = H5Dopen2(dset_id[0], "dataset", H5P_DEFAULT);
    if (dataset_id == H5I_INVALID_HID) {
        fprintf(stderr, "H5Dopen2 failed\n");
    } else {
        H5Dclose(dataset_id);
    }

    // Fuzz H5Dcreate2
    hid_t new_dataset_id = H5Dcreate2(dset_id[0], "new_dataset", mem_type_id[0], mem_space_id[0], H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (new_dataset_id == H5I_INVALID_HID) {
        fprintf(stderr, "H5Dcreate2 failed\n");
    } else {
        H5Dclose(new_dataset_id);
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    