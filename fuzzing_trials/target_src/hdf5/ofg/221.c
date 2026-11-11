#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    // Initialize variables
    hid_t src_loc_id = H5P_DEFAULT; // Default property list
    hid_t dst_loc_id = H5P_DEFAULT; // Default property list

    // Ensure size is sufficient for null-terminated strings
    if (size < 2) return 0;

    // Allocate memory for source and destination names
    char *src_name = (char *)malloc(size / 2 + 1);
    char *dst_name = (char *)malloc(size / 2 + 1);

    if (src_name == NULL || dst_name == NULL) {
        free(src_name);
        free(dst_name);
        return 0;
    }

    // Copy data into source and destination names
    memcpy(src_name, data, size / 2);
    memcpy(dst_name, data + size / 2, size / 2);

    // Null-terminate the strings
    src_name[size / 2] = '\0';
    dst_name[size / 2] = '\0';

    // Call the function-under-test
    H5Gmove2(src_loc_id, src_name, dst_loc_id, dst_name);

    // Free allocated memory
    free(src_name);
    free(dst_name);

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

    LLVMFuzzerTestOneInput_221(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
