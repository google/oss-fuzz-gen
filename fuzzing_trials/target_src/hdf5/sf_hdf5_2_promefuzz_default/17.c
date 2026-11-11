// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dwrite_chunk at H5D.c:1491:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dread_chunk1 at H5Ddeprec.c:350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dread_chunk1 at H5Ddeprec.c:350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include "H5Dpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hsize_t) * 3 + sizeof(uint32_t) + sizeof(size_t)) {
        return 0;
    }

    write_dummy_file();

    hsize_t offset[3];
    memcpy(offset, Data, sizeof(hsize_t) * 3);
    Data += sizeof(hsize_t) * 3;
    Size -= sizeof(hsize_t) * 3;

    uint32_t filters;
    memcpy(&filters, Data, sizeof(uint32_t));
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    size_t data_size;
    memcpy(&data_size, Data, sizeof(size_t));
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    hid_t loc_id = 0; // Assume a valid location ID
    hid_t type_id = 0; // Assume a valid type ID
    hid_t space_id = 0; // Assume a valid space ID
    hid_t lcpl_id = 0; // Assume a valid link creation property list ID
    hid_t dcpl_id = 0; // Assume a valid dataset creation property list ID
    hid_t dapl_id = 0; // Assume a valid dataset access property list ID

    hid_t dset_id = H5Dcreate2(loc_id, "dummy_dataset", type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dset_id < 0) {
        return 0;
    }

    herr_t status;
    void *buf = malloc(data_size);
    if (!buf) {
        H5Dclose(dset_id);
        return 0;
    }

    status = H5Dwrite_chunk(dset_id, 0, filters, offset, data_size, buf);
    if (status < 0) {
        free(buf);
        H5Dclose(dset_id);
        return 0;
    }

    status = H5Dread_chunk1(dset_id, 0, offset, &filters, buf);
    if (status < 0) {
        free(buf);
        H5Dclose(dset_id);
        return 0;
    }

    status = H5Dread_chunk1(dset_id, 0, offset, &filters, buf);
    if (status < 0) {
        free(buf);
        H5Dclose(dset_id);
        return 0;
    }

    free(buf);

    status = H5Dclose(dset_id);
    if (status < 0) {
        return 0;
    }

    status = H5Dclose(dset_id);
    if (status < 0) {
        return 0;
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    