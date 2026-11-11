#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 4) return 0;

    // Extract two hid_t values from the input data
    hid_t loc_id1 = (hid_t)data[0];
    hid_t loc_id2 = (hid_t)data[1];

    // Extract an H5L_type_t value from the input data
    H5L_type_t link_type = (H5L_type_t)data[2];

    // Use the remaining data as strings for name1 and name2
    size_t name1_len = size / 2;
    size_t name2_len = size - name1_len;
    
    char *name1 = (char *)malloc(name1_len + 1);
    char *name2 = (char *)malloc(name2_len + 1);

    if (name1 == NULL || name2 == NULL) {
        free(name1);
        free(name2);
        return 0;
    }

    // Copy data into name1 and name2
    for (size_t i = 0; i < name1_len; i++) {
        name1[i] = (char)data[3 + i];
    }
    name1[name1_len] = '\0';

    for (size_t i = 0; i < name2_len; i++) {
        name2[i] = (char)data[3 + name1_len + i];
    }
    name2[name2_len] = '\0';

    // Call the function-under-test
    H5Glink2(loc_id1, name1, link_type, loc_id2, name2);

    // Clean up
    free(name1);
    free(name2);

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

    LLVMFuzzerTestOneInput_50(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
