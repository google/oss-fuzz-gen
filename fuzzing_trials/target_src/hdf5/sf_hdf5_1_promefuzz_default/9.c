// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_eoa at H5F.c:2606:1 in H5Fpublic.h
// H5Gget_num_objs at H5Gdeprec.c:885:1 in H5Gpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fget_obj_ids at H5F.c:333:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"
#include "H5Ppublic.h"
#include "H5Spublic.h"

static hid_t create_dummy_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file.\n");
        exit(EXIT_FAILURE);
    }
    return file_id;
}

static void close_file(hid_t file_id) {
    if (H5Fclose(file_id) < 0) {
        fprintf(stderr, "Failed to close file.\n");
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t)) return 0;

    hid_t file_id = create_dummy_file();
    haddr_t eoa;
    hsize_t num_objs;
    H5G_info_t ginfo;
    hid_t obj_id_list[10];
    char cur_name[] = "cur_name";
    char new_name[] = "new_name";
    H5G_link_t link_type = H5G_LINK_HARD;
    hid_t dset_id = -1;
    hid_t mem_type_id = H5T_NATIVE_INT;
    hid_t mem_space_id = H5S_ALL;
    hid_t file_space_id = H5S_ALL;
    hid_t dxpl_id = H5P_DEFAULT;
    int buf[10];

    // Fuzzing H5Fget_eoa
    H5Fget_eoa(file_id, &eoa);

    // Fuzzing H5Gget_num_objs
    H5Gget_num_objs(file_id, &num_objs);

    // Fuzzing H5Gget_info
    H5Gget_info(file_id, &ginfo);

    // Fuzzing H5Fget_obj_ids
    H5Fget_obj_ids(file_id, H5F_OBJ_ALL, 10, obj_id_list);

    // Fuzzing H5Glink2
    H5Glink2(file_id, cur_name, link_type, file_id, new_name);

    // Fuzzing H5Dwrite
    H5Dwrite(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf);

    close_file(file_id);
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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    