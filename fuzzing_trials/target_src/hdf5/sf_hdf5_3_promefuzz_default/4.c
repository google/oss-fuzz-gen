// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fget_obj_count at H5F.c:216:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gopen2 at H5G.c:429:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
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
#include "H5Ppublic.h"

static hid_t create_file(const char *filename) {
    return H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t open_file(const char *filename) {
    return H5Fopen(filename, H5F_ACC_RDWR, H5P_DEFAULT);
}

static herr_t close_file(hid_t file_id) {
    return H5Fclose(file_id);
}

static hid_t create_group(hid_t loc_id, const char *name) {
    return H5Gcreate2(loc_id, name, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
}

static hid_t open_group(hid_t loc_id, const char *name) {
    return H5Gopen2(loc_id, name, H5P_DEFAULT);
}

static herr_t close_group(hid_t group_id) {
    return H5Gclose(group_id);
}

static herr_t mount_file(hid_t loc_id, const char *name, hid_t child_id) {
    return H5Fmount(loc_id, name, child_id, H5P_DEFAULT);
}

static herr_t unmount_file(hid_t loc_id, const char *name) {
    return H5Funmount(loc_id, name);
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    const char *filename = "./dummy_file";
    hid_t file_id, group_id, child_id;
    herr_t status;

    // Create and close files and groups multiple times
    for (int i = 0; i < 5; i++) {
        file_id = create_file(filename);
        if (file_id < 0) return 0;

        group_id = create_group(file_id, "group1");
        if (group_id < 0) {
            close_file(file_id);
            return 0;
        }
        close_group(group_id);

        group_id = create_group(file_id, "group2");
        if (group_id < 0) {
            close_file(file_id);
            return 0;
        }
        close_group(group_id);

        close_file(file_id);
    }

    // Open, mount, and unmount files
    for (int i = 0; i < 5; i++) {
        file_id = open_file(filename);
        if (file_id < 0) return 0;

        child_id = open_file(filename);
        if (child_id < 0) {
            close_file(file_id);
            return 0;
        }

        status = mount_file(file_id, "/", child_id);
        if (status < 0) {
            close_file(child_id);
            close_file(file_id);
            return 0;
        }

        status = unmount_file(file_id, "/");
        if (status < 0) {
            close_file(child_id);
            close_file(file_id);
            return 0;
        }

        close_file(child_id);
        close_file(file_id);
    }

    // Open groups and get object counts
    file_id = open_file(filename);
    if (file_id < 0) return 0;

    group_id = open_group(file_id, "group1");
    if (group_id >= 0) {
        close_group(group_id);
    }

    group_id = open_group(file_id, "group2");
    if (group_id >= 0) {
        close_group(group_id);
    }

    ssize_t obj_count = H5Fget_obj_count(file_id, H5F_OBJ_ALL);
    if (obj_count < 0) {
        close_file(file_id);
        return 0;
    }

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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    