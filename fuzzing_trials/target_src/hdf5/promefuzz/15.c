// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fget_filesize at H5F.c:1659:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_vfd_handle at H5F.c:422:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_intent at H5F.c:1540:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_info2 at H5F.c:2055:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fget_name at H5F.c:1999:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Ppublic.h"

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite("dummy data", 1, 10, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    write_dummy_file("./dummy_file");

    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    hsize_t file_size;
    if (H5Fget_filesize(file_id, &file_size) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    void *file_handle;
    if (H5Fget_vfd_handle(file_id, H5P_DEFAULT, &file_handle) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    unsigned intent;
    if (H5Fget_intent(file_id, &intent) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    H5F_info2_t file_info;
    if (H5Fget_info2(file_id, &file_info) < 0) {
        H5Fclose(file_id);
        return 0;
    }

    char name[256];
    ssize_t name_len = H5Fget_name(file_id, name, sizeof(name));
    if (name_len < 0) {
        H5Fclose(file_id);
        return 0;
    }

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    