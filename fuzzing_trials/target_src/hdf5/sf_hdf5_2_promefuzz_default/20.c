// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Acreate1 at H5Adeprec.c:103:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Dcreate1 at H5Ddeprec.c:98:1 in H5Dpublic.h
// H5Aget_num_attrs at H5Adeprec.c:303:1 in H5Apublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Apublic.h>

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void close_hid(hid_t id) {
    if (id >= 0) {
        H5Oclose(id);
    }
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Ensure null-terminated strings
    char *name = (char *)malloc(Size + 1);
    if (!name) return 0;
    memcpy(name, Data, Size);
    name[Size] = '\0';

    hid_t file_id = create_dummy_file();
    if (file_id < 0) {
        free(name);
        return 0;
    }

    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t type_id = H5Tcopy(H5T_NATIVE_INT);
    
    if (space_id < 0 || type_id < 0) {
        close_hid(file_id);
        free(name);
        return 0;
    }

    // Fuzz H5Acreate1
    hid_t attr_id = H5Acreate1(file_id, name, type_id, space_id, H5P_DEFAULT);
    close_hid(attr_id);

    // Fuzz H5Aopen_name
    attr_id = H5Aopen_name(file_id, name);
    close_hid(attr_id);

    // Fuzz H5Dcreate1
    hid_t dset_id = H5Dcreate1(file_id, name, type_id, space_id, H5P_DEFAULT);
    close_hid(dset_id);

    // Fuzz H5Aget_num_attrs
    int num_attrs = H5Aget_num_attrs(file_id);
    (void)num_attrs; // Suppress unused variable warning

    // Fuzz H5Dcreate2
    dset_id = H5Dcreate2(file_id, name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    close_hid(dset_id);

    // Fuzz H5Aopen_by_name
    attr_id = H5Aopen_by_name(file_id, name, name, H5P_DEFAULT, H5P_DEFAULT);
    close_hid(attr_id);

    // Cleanup
    close_hid(space_id);
    close_hid(type_id);
    close_hid(file_id);
    free(name);

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    