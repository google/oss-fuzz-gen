// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dget_chunk_storage_size at H5D.c:2218:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread_chunk2 at H5D.c:1181:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread_chunk2 at H5D.c:1181:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dwrite_chunk at H5D.c:1491:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fflush at H5F.c:957:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dread at H5D.c:1041:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <hdf5.h>
#include "H5Dpublic.h"
#include "H5Fpublic.h"

static hid_t create_file() {
    return H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t create_dataspace() {
    hsize_t dims[2] = {10, 10}; // Example dimensions
    return H5Screate_simple(2, dims, NULL);
}

static hid_t create_datatype() {
    return H5Tcopy(H5T_NATIVE_INT);
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hsize_t) * 2 + sizeof(uint32_t) + sizeof(size_t)) {
        return 0;
    }

    hid_t file_id = create_file();
    if (file_id < 0) return 0;

    hid_t space_id = create_dataspace();
    if (space_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    hid_t type_id = create_datatype();
    if (type_id < 0) {
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hid_t dset_id = H5Dcreate2(file_id, "dataset", type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (dset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    uint32_t filters = *(uint32_t *)Data;
    hsize_t offset[2] = {*(hsize_t *)(Data + sizeof(uint32_t)), *(hsize_t *)(Data + sizeof(uint32_t) + sizeof(hsize_t))};
    size_t data_size = *(size_t *)(Data + sizeof(uint32_t) + sizeof(hsize_t) * 2);
    const void *buf = Data + sizeof(uint32_t) + sizeof(hsize_t) * 2 + sizeof(size_t);

    if (data_size > Size - (sizeof(uint32_t) + sizeof(hsize_t) * 2 + sizeof(size_t))) {
        data_size = Size - (sizeof(uint32_t) + sizeof(hsize_t) * 2 + sizeof(size_t));
    }

    if (H5Dwrite_chunk(dset_id, H5P_DEFAULT, filters, offset, data_size, buf) < 0) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    if (H5Fflush(file_id, H5F_SCOPE_LOCAL) < 0) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    if (H5Dclose(dset_id) < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) {
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    void *read_buf = malloc(data_size);
    if (!read_buf) {
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    if (H5Dread(dset_id, type_id, H5S_ALL, H5S_ALL, H5P_DEFAULT, read_buf) < 0) {
        free(read_buf);
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    hsize_t chunk_size;
    if (H5Dget_chunk_storage_size(dset_id, offset, &chunk_size) < 0) {
        free(read_buf);
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    size_t buf_size = chunk_size;
    uint32_t read_filters;
    if (H5Dread_chunk2(dset_id, H5P_DEFAULT, offset, &read_filters, read_buf, &buf_size) < 0) {
        free(read_buf);
        H5Dclose(dset_id);
        H5Tclose(type_id);
        H5Sclose(space_id);
        H5Fclose(file_id);
        return 0;
    }

    // Repeat H5Dread_chunk2 to explore more states
    for (int i = 0; i < 3; ++i) {
        if (H5Dread_chunk2(dset_id, H5P_DEFAULT, offset, &read_filters, read_buf, &buf_size) < 0) {
            break;
        }
    }

    free(read_buf);
    H5Dclose(dset_id);
    H5Tclose(type_id);
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    