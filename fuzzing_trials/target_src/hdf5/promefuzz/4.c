// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Dopen2 at H5D.c:393:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aopen at H5A.c:531:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aread at H5A.c:1014:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aget_space at H5A.c:1084:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aget_storage_size at H5A.c:1366:1 in H5Apublic.h
// H5Aget_info at H5A.c:1405:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Aopen at H5A.c:531:1 in H5Apublic.h
// H5Dclose at H5D.c:463:1 in H5Dpublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Awrite at H5A.c:908:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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
#include <H5Dpublic.h>
#include <H5Fpublic.h>
#include <H5Apublic.h>
#include <H5Ppublic.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    // Open the file
    hid_t file_id = H5Fopen("./dummy_file", H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) return 0;

    // Open the dataset
    hid_t dataset_id = H5Dopen2(file_id, "dummy_dataset", H5P_DEFAULT);
    if (dataset_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Open the attribute
    hid_t attr_id = H5Aopen(dataset_id, "dummy_attribute", H5P_DEFAULT);
    if (attr_id < 0) {
        H5Dclose(dataset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Read the attribute
    char buf[1024];
    herr_t status = H5Aread(attr_id, H5T_NATIVE_CHAR, buf);
    if (status < 0) {
        H5Aclose(attr_id);
        H5Dclose(dataset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get attribute space
    hid_t space_id = H5Aget_space(attr_id);
    if (space_id < 0) {
        H5Aclose(attr_id);
        H5Dclose(dataset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Get storage size
    hsize_t storage_size = H5Aget_storage_size(attr_id);

    // Get attribute info
    H5A_info_t ainfo;
    status = H5Aget_info(attr_id, &ainfo);

    // Close the first attribute
    H5Aclose(attr_id);

    // Open the attribute again
    attr_id = H5Aopen(dataset_id, "dummy_attribute", H5P_DEFAULT);
    if (attr_id < 0) {
        H5Dclose(dataset_id);
        H5Fclose(file_id);
        return 0;
    }

    // Write to the attribute
    status = H5Awrite(attr_id, H5T_NATIVE_CHAR, buf);

    // Close the attribute and dataset
    H5Aclose(attr_id);
    H5Dclose(dataset_id);

    // Close the file
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    