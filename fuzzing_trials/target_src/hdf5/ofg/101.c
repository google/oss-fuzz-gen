#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract necessary parameters
    if (size < sizeof(hid_t) + sizeof(H5F_mem_t) + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    size_t offset = 0;
    hid_t file_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);

    H5F_mem_t type = *((H5F_mem_t *)(data + offset));
    offset += sizeof(H5F_mem_t);

    size_t nsects = *((size_t *)(data + offset));
    offset += sizeof(size_t);

    // Allocate memory for H5F_sect_info_t array
    H5F_sect_info_t *sect_info = (H5F_sect_info_t *)malloc(nsects * sizeof(H5F_sect_info_t));
    if (sect_info == NULL) {
        return 0; // Memory allocation failed
    }

    // Call the function-under-test
    ssize_t result = H5Fget_free_sections(file_id, type, nsects, sect_info);

    // Clean up
    free(sect_info);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_101(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
