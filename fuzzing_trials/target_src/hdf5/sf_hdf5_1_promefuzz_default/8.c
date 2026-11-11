// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Gget_info_by_name at H5G.c:688:1 in H5Gpublic.h
// H5Grefresh at H5G.c:992:1 in H5Gpublic.h
// H5Gflush at H5G.c:954:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <H5Gpublic.h>
#include <H5Ppublic.h>
#include <H5Fpublic.h>
#include <H5Ipublic.h>
#include <H5Epublic.h>
#include <stdio.h>

static void handle_error(herr_t status, const char *message) {
    if (status < 0) {
        fprintf(stderr, "Error: %s\n", message);
        H5Eprint(H5E_DEFAULT, stderr);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a file for testing
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Failed to create file.\n");
        return 0;
    }

    // Create a group in the file
    hid_t group_id = H5Gcreate2(file_id, "test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        fprintf(stderr, "Failed to create group.\n");
        return 0;
    }

    // Fuzz H5Gget_info
    H5G_info_t ginfo;
    herr_t status = H5Gget_info(group_id, &ginfo);
    handle_error(status, "H5Gget_info failed");

    // Fuzz H5Gget_info_by_name
    status = H5Gget_info_by_name(file_id, "test_group", &ginfo, H5P_DEFAULT);
    handle_error(status, "H5Gget_info_by_name failed");

    // Fuzz H5Grefresh
    status = H5Grefresh(group_id);
    handle_error(status, "H5Grefresh failed");

    // Fuzz H5Gflush
    status = H5Gflush(group_id);
    handle_error(status, "H5Gflush failed");

    // Close the group
    status = H5Gclose(group_id);
    handle_error(status, "H5Gclose failed");

    // Close the file
    status = H5Fclose(file_id);
    handle_error(status, "H5Fclose failed");

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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    