#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_176(const uint8_t *data, size_t size) {
    // Define and initialize variables
    hid_t loc_id = H5P_DEFAULT; // Default property list
    hid_t aapl_id = H5P_DEFAULT; // Attribute access property list
    hid_t lapl_id = H5P_DEFAULT; // Link access property list

    // Ensure there is enough data to extract meaningful strings
    if (size < 2) {
        return 0;
    }

    // Calculate lengths for the strings
    size_t name_len = data[0] % (size - 1) + 1; // Ensure at least 1 character
    size_t attr_name_len = data[1] % (size - 1) + 1; // Ensure at least 1 character

    // Ensure that the total length does not exceed the size
    if (name_len + attr_name_len + 2 > size) {
        return 0;
    }

    // Create strings for the object name and attribute name
    char *name = (char *)malloc(name_len + 1);
    char *attr_name = (char *)malloc(attr_name_len + 1);

    if (name == NULL || attr_name == NULL) {
        free(name);
        free(attr_name);
        return 0;
    }

    // Copy data into the strings and null-terminate
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';
    memcpy(attr_name, data + 2 + name_len, attr_name_len);
    attr_name[attr_name_len] = '\0';

    // Call the function-under-test
    hid_t result = H5Aopen_by_name(loc_id, name, attr_name, aapl_id, lapl_id);

    // Clean up
    free(name);
    free(attr_name);

    // Close the attribute if it was successfully opened
    if (result >= 0) {
        H5Aclose(result);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_176(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
