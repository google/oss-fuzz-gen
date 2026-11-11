// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_vfd_handle at H5F.c:422:1 in H5Fpublic.h
// H5Fget_filesize at H5F.c:1659:1 in H5Fpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Fis_accessible at H5F.c:464:1 in H5Fpublic.h
// H5Fget_freespace at H5F.c:1617:1 in H5Fpublic.h
// H5Fget_free_sections at H5F.c:2147:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hdf5.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static void fuzz_H5Fget_vfd_handle(hid_t file_id) {
    void *file_handle = NULL;
    H5Fget_vfd_handle(file_id, H5P_DEFAULT, &file_handle);
}

static void fuzz_H5Fget_filesize(hid_t file_id) {
    hsize_t size;
    H5Fget_filesize(file_id, &size);
}

static void fuzz_H5Fget_obj_ids(hid_t file_id) {
    hid_t obj_id_list[10];
    H5Fget_obj_ids(file_id, H5F_OBJ_ALL, 10, obj_id_list);
}

static void fuzz_H5Fis_accessible() {
    H5Fis_accessible("./dummy_file", H5P_DEFAULT);
}

static void fuzz_H5Fget_freespace(hid_t file_id) {
    H5Fget_freespace(file_id);
}

static void fuzz_H5Fget_free_sections(hid_t file_id) {
    H5F_sect_info_t sect_info[10];
    H5Fget_free_sections(file_id, H5FD_MEM_DEFAULT, 10, sect_info);
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    fuzz_H5Fget_vfd_handle(file_id);
    fuzz_H5Fget_filesize(file_id);
    fuzz_H5Fget_obj_ids(file_id);
    fuzz_H5Fis_accessible();
    fuzz_H5Fget_freespace(file_id);
    fuzz_H5Fget_free_sections(file_id);

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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    