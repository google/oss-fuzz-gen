// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Glink2 at H5Gdeprec.c:378:1 in H5Gpublic.h
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Acreate2 at H5A.c:221:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen_name at H5Adeprec.c:176:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Gcreate2 at H5G.c:222:1 in H5Gpublic.h
// H5Gclose at H5G.c:864:1 in H5Gpublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
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
#include <H5Apublic.h>
#include <H5Dpublic.h>
#include <H5Gpublic.h>

#define DUMMY_FILE "./dummy_file"

static void write_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Ensure the dummy file is present
    write_dummy_file();

    // Initialize HDF5 library
    hid_t file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Prepare buffers
    char cur_name[256], new_name[256], obj_name[256], attr_name[256];
    snprintf(cur_name, sizeof(cur_name), "cur_name_%zu", Size);
    snprintf(new_name, sizeof(new_name), "new_name_%zu", Size);
    snprintf(obj_name, sizeof(obj_name), "obj_name_%zu", Size);
    snprintf(attr_name, sizeof(attr_name), "attr_name_%zu", Size);

    // Use Data to determine link type and other parameters
    H5G_link_t link_type = (Data[0] % 2 == 0) ? H5G_LINK_HARD : H5G_LINK_SOFT;
    hid_t type_id = H5T_NATIVE_INT;
    hid_t space_id = H5Screate(H5S_SCALAR);
    hid_t acpl_id = H5P_DEFAULT;
    hid_t aapl_id = H5P_DEFAULT;
    hid_t lcpl_id = H5P_DEFAULT;
    hid_t gcpl_id = H5P_DEFAULT;
    hid_t gapl_id = H5P_DEFAULT;
    hid_t dcpl_id = H5P_DEFAULT;
    hid_t dapl_id = H5P_DEFAULT;

    // Fuzz H5Glink2
    H5Glink2(file_id, cur_name, link_type, file_id, new_name);

    // Fuzz H5Aopen_by_name
    hid_t attr_id = H5Aopen_by_name(file_id, obj_name, attr_name, aapl_id, H5P_DEFAULT);
    if (attr_id >= 0) H5Aclose(attr_id);

    // Fuzz H5Acreate2
    attr_id = H5Acreate2(file_id, attr_name, type_id, space_id, acpl_id, aapl_id);
    if (attr_id >= 0) H5Aclose(attr_id);

    // Fuzz H5Aopen_name
    attr_id = H5Aopen_name(file_id, attr_name);
    if (attr_id >= 0) H5Aclose(attr_id);

    // Fuzz H5Gcreate2
    hid_t group_id = H5Gcreate2(file_id, cur_name, lcpl_id, gcpl_id, gapl_id);
    if (group_id >= 0) H5Gclose(group_id);

    // Fuzz H5Dcreate2
    hid_t dataset_id = H5Dcreate2(file_id, cur_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset_id >= 0) H5Dclose(dataset_id);

    // Cleanup
    H5Sclose(space_id);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    