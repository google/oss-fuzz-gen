// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Freopen at H5F.c:1440:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Dpublic.h"

#define DUMMY_FILE "./dummy_file"

static void initialize_dummy_file() {
    hid_t file_id = H5Fcreate(DUMMY_FILE, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create dummy file\n");
        exit(EXIT_FAILURE);
    }
    H5Fclose(file_id);
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    initialize_dummy_file();

    hid_t file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to open dummy file\n");
        return 0;
    }

    // Fuzz H5Freopen
    hid_t new_file_id = H5Freopen(file_id);
    if (new_file_id >= 0) {
        H5Fclose(new_file_id);
    }

    // Fuzz H5Dopen2
    char dataset_name[256];
    snprintf(dataset_name, sizeof(dataset_name), "dataset_%zu", Size);
    hid_t dataset_id = H5Dopen2(file_id, dataset_name, H5P_DEFAULT);
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

    // Fuzz H5Gget_info
    H5G_info_t ginfo;
    if (H5Gget_info(file_id, &ginfo) < 0) {
        fprintf(stderr, "Failed to get group info\n");
    }

    // Fuzz H5Funmount
    char mount_point[256];
    snprintf(mount_point, sizeof(mount_point), "mount_point_%zu", Size);
    if (H5Funmount(file_id, mount_point) < 0) {
        fprintf(stderr, "Failed to unmount\n");
    }

    // Fuzz H5Fmount
    hid_t child_file_id = H5Fcreate("child_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (child_file_id >= 0) {
        if (H5Fmount(file_id, mount_point, child_file_id, H5P_DEFAULT) < 0) {
            fprintf(stderr, "Failed to mount\n");
        }
        H5Fclose(child_file_id);
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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    