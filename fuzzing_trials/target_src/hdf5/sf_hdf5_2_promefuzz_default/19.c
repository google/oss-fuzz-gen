// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Aopen_by_name at H5A.c:657:1 in H5Apublic.h
// H5Aget_space at H5A.c:1084:1 in H5Apublic.h
// H5Aget_info at H5A.c:1405:1 in H5Apublic.h
// H5Aget_type at H5A.c:1128:1 in H5Apublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dcreate2 at H5D.c:179:1 in H5Dpublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Dpublic.h>
#include <H5Apublic.h>
#include <H5Ppublic.h> // Include for H5P_DEFAULT

#define DUMMY_FILE "./dummy_file"

static void prepare_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        // Write some dummy data to the file to simulate an HDF5 file
        const char *dummy_data = "HDF5 dummy data";
        fwrite(dummy_data, sizeof(char), strlen(dummy_data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) * 7 + 2) {
        return 0;
    }

    prepare_dummy_file();

    // Extract IDs and names from input data
    hid_t loc_id = *(const hid_t *)Data;
    hid_t attr_id = *(const hid_t *)(Data + sizeof(hid_t));
    hid_t type_id = *(const hid_t *)(Data + 2 * sizeof(hid_t));
    hid_t space_id = *(const hid_t *)(Data + 3 * sizeof(hid_t));
    hid_t lcpl_id = *(const hid_t *)(Data + 4 * sizeof(hid_t));
    hid_t dcpl_id = *(const hid_t *)(Data + 5 * sizeof(hid_t));
    hid_t dapl_id = *(const hid_t *)(Data + 6 * sizeof(hid_t));

    size_t offset = 7 * sizeof(hid_t);
    if (Size <= offset) {
        return 0;
    }

    // Ensure null-termination for obj_name
    size_t max_obj_name_len = strnlen((const char *)(Data + offset), Size - offset);
    if (max_obj_name_len == Size - offset) {
        return 0; // No null-terminator found within bounds
    }
    const char *obj_name = (const char *)(Data + offset);
    offset += max_obj_name_len + 1;

    if (Size <= offset) {
        return 0;
    }

    // Ensure null-termination for attr_name
    size_t max_attr_name_len = strnlen((const char *)(Data + offset), Size - offset);
    if (max_attr_name_len == Size - offset) {
        return 0; // No null-terminator found within bounds
    }
    const char *attr_name = (const char *)(Data + offset);
    offset += max_attr_name_len + 1;

    if (Size <= offset) {
        return 0;
    }

    // Buffers for H5Awrite
    void *buf = (void *)(Data + offset);

    // Call H5Aopen_by_name
    hid_t attribute = H5Aopen_by_name(loc_id, obj_name, attr_name, H5P_DEFAULT, H5P_DEFAULT);
    if (attribute >= 0) {
        // Call H5Aget_space
        hid_t dataspace = H5Aget_space(attribute);
        if (dataspace >= 0) {
            // Call H5Aget_info
            H5A_info_t ainfo;
            H5Aget_info(attribute, &ainfo);

            // Call H5Aget_type
            hid_t datatype = H5Aget_type(attribute);
            if (datatype >= 0) {
                // Call H5Awrite
                H5Awrite(attribute, datatype, buf);
                H5Tclose(datatype);
            }
            H5Sclose(dataspace);
        }
        H5Aclose(attribute);
    }

    // Call H5Dcreate2
    hid_t dataset = H5Dcreate2(loc_id, obj_name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);
    if (dataset >= 0) {
        H5Dclose(dataset);
    }

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    