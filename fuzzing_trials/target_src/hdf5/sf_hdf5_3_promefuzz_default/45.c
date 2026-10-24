// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Gget_linkval at H5Gdeprec.c:633:1 in H5Gpublic.h
// H5Gmove2 at H5Gdeprec.c:512:1 in H5Gpublic.h
// H5Gmove at H5Gdeprec.c:469:1 in H5Gpublic.h
// H5Glink at H5Gdeprec.c:294:1 in H5Gpublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
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
#include <H5Gpublic.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("This is a dummy HDF5 file for fuzzing.", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize HDF5 library
    H5open();

    // Prepare dummy file
    write_dummy_file();

    // Open the dummy file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Target API: H5Glink2
    const char *cur_name = "existing_object";
    const char *new_name = "new_link_name";
    H5Glink2(file_id, cur_name, H5L_TYPE_HARD, file_id, new_name);

    // Target API: H5Gget_linkval
    char buf[1024];
    H5Gget_linkval(file_id, new_name, sizeof(buf), buf);

    // Target API: H5Gmove2
    const char *src_name = "src_object";
    const char *dst_name = "dst_object";
    H5Gmove2(file_id, src_name, file_id, dst_name);

    // Target API: H5Gmove
    H5Gmove(file_id, src_name, dst_name);

    // Target API: H5Glink
    H5Glink(file_id, H5L_TYPE_SOFT, cur_name, new_name);

    // Target API: H5Gcreate2
    hid_t group_id = H5Gcreate2(file_id, "new_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

    // Clean up
    H5Fclose(file_id);
    H5close();

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
    