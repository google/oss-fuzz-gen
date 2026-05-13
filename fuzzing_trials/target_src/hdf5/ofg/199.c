#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for our needs
    if (size < 3) {
        return 0;
    }

    // Initialize dummy values for hid_t
    hid_t loc_id = (hid_t)data[0];
    hid_t lapl_id = (hid_t)data[1];

    // Create strings from the data
    size_t name_len = size / 3;
    size_t attr_name_len = size / 3;
    
    char *name = (char *)malloc(name_len + 1);
    char *attr_name = (char *)malloc(attr_name_len + 1);

    if (name == NULL || attr_name == NULL) {
        free(name);
        free(attr_name);
        return 0;
    }

    // Copy data into the strings and null-terminate
    for (size_t i = 0; i < name_len; i++) {
        name[i] = (char)data[i + 2];
    }
    name[name_len] = '\0';

    for (size_t i = 0; i < attr_name_len; i++) {
        attr_name[i] = (char)data[i + 2 + name_len];
    }
    attr_name[attr_name_len] = '\0';

    // Call the function-under-test
    htri_t result = H5Aexists_by_name(loc_id, name, attr_name, lapl_id);

    // Cleanup
    free(name);
    free(attr_name);

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

    LLVMFuzzerTestOneInput_199(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
