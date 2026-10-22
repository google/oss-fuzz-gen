// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fcreate at H5F.c:638:1 in H5Fpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Gget_info at H5G.c:582:1 in H5Gpublic.h
// H5Fmount at H5F.c:1183:1 in H5Fpublic.h
// H5Funmount at H5F.c:1301:1 in H5Fpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>

static hid_t create_file() {
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        fprintf(stderr, "Error creating file\n");
    }
    return file_id;
}

static void close_file(hid_t file_id) {
    if (H5Fclose(file_id) < 0) {
        fprintf(stderr, "Error closing file\n");
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hid_t file_id = create_file();
    if (file_id < 0) return 0;

    // Prepare variables for H5Dcreate2
    hid_t dataset_id = H5I_INVALID_HID;
    hid_t dtype_id = H5T_NATIVE_INT;
    hsize_t dims[1] = {10};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    const char *dataset_name = "dataset";

    if (space_id >= 0) {
        dataset_id = H5Dcreate2(file_id, dataset_name, dtype_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
        if (dataset_id < 0) {
            fprintf(stderr, "Error creating dataset\n");
        }
    }

    // Test H5Dopen2
    hid_t open_id = H5Dopen2(file_id, dataset_name, H5P_DEFAULT);
    if (open_id < 0) {
        fprintf(stderr, "Error opening dataset\n");
    }

    // Test H5Gget_info
    H5G_info_t ginfo;
    if (H5Gget_info(file_id, &ginfo) < 0) {
        fprintf(stderr, "Error getting group info\n");
    }

    // Test H5Fmount and H5Funmount
    if (H5Fmount(file_id, "/mount_point", file_id, H5P_DEFAULT) < 0) {
        fprintf(stderr, "Error mounting file\n");
    }
    if (H5Funmount(file_id, "/mount_point") < 0) {
        fprintf(stderr, "Error unmounting file\n");
    }

    // Close resources
    if (dataset_id >= 0 && H5Dclose(dataset_id) < 0) {
        fprintf(stderr, "Error closing dataset\n");
    }
    if (open_id >= 0 && H5Dclose(open_id) < 0) {
        fprintf(stderr, "Error closing opened dataset\n");
    }
    if (space_id >= 0 && H5Sclose(space_id) < 0) {
        fprintf(stderr, "Error closing dataspace\n");
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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    