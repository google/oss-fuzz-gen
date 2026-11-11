#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the input data
    hid_t dataset_id = *(const hid_t *)data;

    // Call the function-under-test
    hid_t access_plist_id = H5Dget_access_plist(dataset_id);

    // Close the access property list if it was successfully created
    if (access_plist_id >= 0) {
        H5Pclose(access_plist_id);
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

    LLVMFuzzerTestOneInput_188(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
