// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Glink at H5Gdeprec.c:294:1 in H5Gpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Gget_linkval at H5Gdeprec.c:633:1 in H5Gpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

static void fuzz_H5Glink(hid_t file_id, const uint8_t *Data, size_t Size) {
    if (Size < 3) return;
    
    H5G_link_t link_type = (H5G_link_t)(Data[0] % 2);
    const char *cur_name = (const char *)(Data + 1);
    size_t cur_name_len = strnlen(cur_name, Size - 1);
    
    if (cur_name_len + 2 >= Size) return;
    
    const char *new_name = (const char *)(Data + 1 + cur_name_len + 1);
    size_t new_name_len = strnlen(new_name, Size - 1 - cur_name_len - 1);
    
    if (cur_name_len + new_name_len + 2 >= Size) return;

    H5Glink(file_id, link_type, cur_name, new_name);
}

static void fuzz_H5Gget_num_objs(hid_t file_id) {
    hsize_t num_objs;
    H5Gget_num_objs(file_id, &num_objs);
}

static void fuzz_H5Gget_info(hid_t file_id) {
    H5G_info_t ginfo;
    H5Gget_info(file_id, &ginfo);
}

static void fuzz_H5Glink2(hid_t file_id, const uint8_t *Data, size_t Size) {
    if (Size < 3) return;
    
    H5G_link_t link_type = (H5G_link_t)(Data[0] % 2);
    const char *cur_name = (const char *)(Data + 1);
    size_t cur_name_len = strnlen(cur_name, Size - 1);
    
    if (cur_name_len + 2 >= Size) return;
    
    const char *new_name = (const char *)(Data + 1 + cur_name_len + 1);
    size_t new_name_len = strnlen(new_name, Size - 1 - cur_name_len - 1);
    
    if (cur_name_len + new_name_len + 2 >= Size) return;

    H5Glink2(file_id, cur_name, link_type, file_id, new_name);
}

static void fuzz_H5Gget_linkval(hid_t file_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *name = (const char *)Data;
    size_t name_len = strnlen(name, Size);
    if (name_len >= Size) return;

    size_t buf_size = Size - name_len - 1;
    char *buf = (char *)malloc(buf_size + 1);

    if (buf) {
        H5Gget_linkval(file_id, name, buf_size, buf);
        free(buf);
    }
}

static void fuzz_H5Dwrite(hid_t file_id, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    hid_t dset_id = H5Dopen2(file_id, "dataset", H5P_DEFAULT);
    if (dset_id < 0) return;

    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;

    H5Dwrite(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, Data);

    H5Dclose(dset_id);
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    hid_t file_id;
    
    // Create a dummy HDF5 file
    file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Fuzz different functions
    fuzz_H5Glink(file_id, Data, Size);
    fuzz_H5Gget_num_objs(file_id);
    fuzz_H5Gget_info(file_id);
    fuzz_H5Glink2(file_id, Data, Size);
    fuzz_H5Gget_linkval(file_id, Data, Size);
    fuzz_H5Dwrite(file_id, Data, Size);

    // Close the file
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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    