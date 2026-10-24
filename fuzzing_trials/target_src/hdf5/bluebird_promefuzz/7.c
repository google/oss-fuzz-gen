#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hdf5/src/H5Fpublic.h"
#include "/src/hdf5/src/H5Apublic.h"
#include "/src/hdf5/src/H5Spublic.h"
#include "/src/hdf5/src/H5Tpublic.h"
#include "/src/hdf5/src/H5Ppublic.h"

static hid_t create_dummy_file() {
    // Create a new file using default properties.
    hid_t file_id = H5Fcreate("./dummy_file", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    return file_id;
}

static hid_t create_dummy_dataspace() {
    // Create a simple dataspace with no elements.
    return H5Screate(H5S_SCALAR);
}

static hid_t create_dummy_datatype() {
    // Create a simple datatype.
    return H5Tcopy(H5T_NATIVE_INT);
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    hid_t file_id = create_dummy_file();
    if (file_id < 0) return 0;

    const char *obj_name = "dummy_object";
    const char *attr_name = "dummy_attribute";

    // Create a dummy dataspace and datatype
    hid_t space_id = create_dummy_dataspace();
    hid_t type_id = create_dummy_datatype();

    if (space_id < 0 || type_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Attempt to open an attribute
    hid_t attr_id = H5Aopen(file_id, attr_name, H5P_DEFAULT);
    if (attr_id >= 0) {
        H5Aclose(attr_id);
    }

    // Attempt to delete an attribute
    H5Adelete(file_id, attr_name);

    // Attempt to create an attribute by name
    hid_t create_attr_id = H5Acreate_by_name(file_id, obj_name, attr_name, type_id, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (create_attr_id >= 0) {
        H5Aclose(create_attr_id);
    }

    // Attempt to delete an attribute by name
    H5Adelete_by_name(file_id, obj_name, attr_name, H5P_DEFAULT);

    // Close the file twice to test behavior
    H5Fclose(file_id);
    H5Fclose(file_id);

    // Cleanup
    H5Sclose(space_id);
    H5Tclose(type_id);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
