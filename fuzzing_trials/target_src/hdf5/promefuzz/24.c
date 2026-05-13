// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Fopen at H5F.c:812:1 in H5Fpublic.h
// H5Aexists at H5A.c:2364:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aexists_by_name at H5A.c:2474:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aopen at H5A.c:531:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aexists at H5A.c:2364:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aexists_by_name at H5A.c:2474:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aread at H5A.c:1014:1 in H5Apublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
// H5Fclose at H5F.c:1027:1 in H5Fpublic.h
// H5Aclose at H5A.c:2194:1 in H5Apublic.h
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

#define DUMMY_FILE "./dummy_file"
#define ATTR_NAME "dummy_attr"
#define OBJ_NAME "dummy_obj"

static void write_dummy_file() {
    FILE *file = fopen(DUMMY_FILE, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(hid_t) + sizeof(hid_t)) {
        return 0;
    }

    // Prepare the environment
    write_dummy_file();

    hid_t file_id = H5Fopen(DUMMY_FILE, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Extract obj_id and type_id from the input data
    hid_t obj_id = *(hid_t *)Data;
    hid_t type_id = *(hid_t *)(Data + sizeof(hid_t));

    // H5Aexists
    htri_t exists = H5Aexists(obj_id, ATTR_NAME);
    if (exists < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // H5Aexists_by_name
    htri_t exists_by_name = H5Aexists_by_name(obj_id, OBJ_NAME, ATTR_NAME, H5P_DEFAULT);
    if (exists_by_name < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // H5Aopen
    hid_t attr_id = H5Aopen(obj_id, ATTR_NAME, H5P_DEFAULT);
    if (attr_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // H5Aexists again
    exists = H5Aexists(obj_id, ATTR_NAME);
    if (exists < 0) {
        H5Aclose(attr_id);
        H5Fclose(file_id);
        return 0;
    }

    // H5Aexists_by_name again
    exists_by_name = H5Aexists_by_name(obj_id, OBJ_NAME, ATTR_NAME, H5P_DEFAULT);
    if (exists_by_name < 0) {
        H5Aclose(attr_id);
        H5Fclose(file_id);
        return 0;
    }

    // Prepare buffer for H5Aread
    void *buf = malloc(1024); // Allocate a buffer
    if (!buf) {
        H5Aclose(attr_id);
        H5Fclose(file_id);
        return 0;
    }

    // H5Aread
    herr_t status = H5Aread(attr_id, type_id, buf);
    if (status < 0) {
        free(buf);
        H5Aclose(attr_id);
        H5Fclose(file_id);
        return 0;
    }

    // H5Aclose
    status = H5Aclose(attr_id);
    if (status < 0) {
        free(buf);
        H5Fclose(file_id);
        return 0;
    }

    // H5Fclose
    status = H5Fclose(file_id);
    if (status < 0) {
        free(buf);
        return 0;
    }

    free(buf);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    