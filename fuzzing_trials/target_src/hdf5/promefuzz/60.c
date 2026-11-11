// This fuzz driver is generated for library hdf5, aiming to fuzz the following functions:
// H5Dget_access_plist at H5D.c:805:1 in H5Dpublic.h
// H5Dwrite at H5D.c:1350:1 in H5Dpublic.h
// H5Dget_type at H5D.c:706:1 in H5Dpublic.h
// H5Dgather at H5D.c:1645:1 in H5Dpublic.h
// H5Dread_multi at H5D.c:1109:1 in H5Dpublic.h
// H5Dget_storage_size at H5D.c:848:1 in H5Dpublic.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <H5Dpublic.h>

static void setup_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fprintf(file, "HDF5 dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    setup_dummy_file();

    // Convert input data to appropriate types
    if (Size < sizeof(hid_t)) return 0;
    hid_t dset_id = *(hid_t *)Data;
    Data += sizeof(hid_t);
    Size -= sizeof(hid_t);

    // H5Dget_access_plist
    hid_t access_plist_id = H5Dget_access_plist(dset_id);
    if (access_plist_id >= 0) {
        // Perform operations on access_plist_id if needed
        // H5Pclose(access_plist_id); // Assuming H5Pclose is the correct function to close the plist
    }

    // H5Dwrite
    if (Size < sizeof(hid_t) * 4 + sizeof(herr_t)) return 0;
    hid_t mem_type_id = *(hid_t *)Data;
    hid_t mem_space_id = *(hid_t *)(Data + sizeof(hid_t));
    hid_t file_space_id = *(hid_t *)(Data + 2 * sizeof(hid_t));
    hid_t dxpl_id = *(hid_t *)(Data + 3 * sizeof(hid_t));
    const void *buf = Data + 4 * sizeof(hid_t);

    herr_t write_status = H5Dwrite(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf);
    if (write_status < 0) {
        // Handle write error
    }

    // H5Dget_type
    hid_t type_id = H5Dget_type(dset_id);
    if (type_id != H5I_INVALID_HID) {
        // Perform operations on type_id if needed
        // H5Tclose(type_id); // Assuming H5Tclose is the correct function to close the type
    }

    // H5Dgather
    if (Size < sizeof(hid_t) * 2 + sizeof(size_t)) return 0;
    hid_t src_space_id = *(hid_t *)Data;
    const void *src_buf = Data + sizeof(hid_t);
    hid_t gather_type_id = *(hid_t *)(Data + sizeof(hid_t) + sizeof(void *));
    size_t dst_buf_size = *(size_t *)(Data + 2 * sizeof(hid_t) + sizeof(void *));
    void *dst_buf = malloc(dst_buf_size);
    if (dst_buf) {
        herr_t gather_status = H5Dgather(src_space_id, src_buf, gather_type_id, dst_buf_size, dst_buf, NULL, NULL);
        if (gather_status < 0) {
            // Handle gather error
        }
        free(dst_buf);
    }

    // H5Dread_multi
    if (Size < sizeof(size_t)) return 0;
    size_t count = *(size_t *)Data;
    if (Size < sizeof(hid_t) * 5 * count + sizeof(void *) * count) return 0;

    hid_t *dset_ids = (hid_t *)(Data + sizeof(size_t));
    hid_t *mem_type_ids = (hid_t *)(Data + sizeof(size_t) + sizeof(hid_t) * count);
    hid_t *mem_space_ids = (hid_t *)(Data + sizeof(size_t) + 2 * sizeof(hid_t) * count);
    hid_t *file_space_ids = (hid_t *)(Data + sizeof(size_t) + 3 * sizeof(hid_t) * count);
    hid_t read_dxpl_id = *(hid_t *)(Data + sizeof(size_t) + 4 * sizeof(hid_t) * count);
    void **read_bufs = (void **)(Data + sizeof(size_t) + 5 * sizeof(hid_t) * count);

    herr_t read_multi_status = H5Dread_multi(count, dset_ids, mem_type_ids, mem_space_ids, file_space_ids, read_dxpl_id, read_bufs);
    if (read_multi_status < 0) {
        // Handle read_multi error
    }

    // H5Dget_storage_size
    hsize_t storage_size = H5Dget_storage_size(dset_id);
    if (storage_size == 0) {
        // Handle potential error or zero storage
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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    