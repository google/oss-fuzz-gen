// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dwrite_chunk at H5D.c:1491:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dread_chunk1 at H5Ddeprec.c:350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dread_chunk1 at H5Ddeprec.c:350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include "H5Ppublic.h" // Include for H5P_DEFAULT

static void write_dummy_data_to_file(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        const char *data = "dummy data for hdf5 testing";
        fwrite(data, sizeof(char), strlen(data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 5 + sizeof(uint32_t) + sizeof(hsize_t) + sizeof(size_t)) {
        return 0;
    }

    write_dummy_data_to_file("./dummy_file");
    
    hid_t loc_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    hid_t type_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    hid_t space_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    hid_t lcpl_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    hid_t dcpl_id = *((hid_t *)Data);
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    uint32_t filters = *((uint32_t *)Data);
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    hsize_t offset = *((hsize_t *)Data);
    Data += sizeof(hsize_t);
    Size -= sizeof(hsize_t);

    size_t data_size = *((size_t *)Data);
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    if (Size < data_size) {
        return 0;
    }

    void *buf = malloc(data_size);
    if (!buf) {
        return 0;
    }
    memcpy(buf, Data, data_size);

    hid_t dapl_id = H5P_DEFAULT;
    hid_t dset_id = H5Dcreate2(loc_id, "./dummy_file", type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dset_id < 0) {
        free(buf);
        return 0;
    }

    herr_t status = H5Dwrite_chunk(dset_id, H5P_DEFAULT, filters, &offset, data_size, buf);
    if (status < 0) {
        H5Dclose(dset_id);
        free(buf);
        return 0;
    }

    uint32_t read_filters;
    status = H5Dread_chunk1(dset_id, H5P_DEFAULT, &offset, &read_filters, buf);
    if (status < 0) {
        H5Dclose(dset_id);
        free(buf);
        return 0;
    }

    status = H5Dread_chunk1(dset_id, H5P_DEFAULT, &offset, &read_filters, buf);
    if (status < 0) {
        H5Dclose(dset_id);
        free(buf);
        return 0;
    }

    H5Dclose(dset_id);
    H5Dclose(dset_id);

    free(buf);
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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    