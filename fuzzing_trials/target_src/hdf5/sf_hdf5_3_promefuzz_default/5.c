// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Gset_comment at H5Gdeprec.c:688:1 in H5Gpublic.h
// H5Gset_comment at H5Gdeprec.c:688:1 in H5Gpublic.h
// H5Gget_comment at H5Gdeprec.c:750:1 in H5Gpublic.h
// H5Gget_comment at H5Gdeprec.c:750:1 in H5Gpublic.h
// H5Glink at H5Gdeprec.c:294:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "H5Fpublic.h"
#include "H5Gpublic.h"
#include "H5Ppublic.h"
#include "H5Lpublic.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("This is a dummy file for HDF5 fuzz testing.\n", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    write_dummy_file();

    // Create a new HDF5 file
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Create three groups
    hid_t group_id1 = H5Gcreate2(file_id, "/group1", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    hid_t group_id2 = H5Gcreate2(file_id, "/group2", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    hid_t group_id3 = H5Gcreate2(file_id, "/group3", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);

    if (group_id1 < 0 || group_id2 < 0 || group_id3 < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Set comments on groups
    H5Gset_comment(group_id1, ".", "This is group1");
    H5Gset_comment(group_id2, ".", "This is group2");

    // Buffer for getting comments
    char comment_buf[256];

    // Get comments from groups
    H5Gget_comment(group_id1, ".", sizeof(comment_buf), comment_buf);
    H5Gget_comment(group_id2, ".", sizeof(comment_buf), comment_buf);

    // Create a link from group3 to group1
    H5Glink(file_id, H5L_TYPE_HARD, "/group1", "/group3_to_group1");

    // Cleanup
    H5Gclose(group_id1);
    H5Gclose(group_id2);
    H5Gclose(group_id3);
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
    