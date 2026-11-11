#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a valid string and an integer
    if (size < sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract an hid_t value from the data
    hid_t file_id = *(const hid_t *)data;

    // Extract a null-terminated string from the remaining data
    const char *group_name = (const char *)(data + sizeof(hid_t));

    // Ensure the string is null-terminated
    char *null_terminated_group_name = (char *)malloc(size - sizeof(hid_t) + 1);
    if (null_terminated_group_name == NULL) {
        return 0;
    }
    memcpy(null_terminated_group_name, group_name, size - sizeof(hid_t));
    null_terminated_group_name[size - sizeof(hid_t)] = '\0';

    // Call the function-under-test
    hid_t group_id = H5Gopen1(file_id, null_terminated_group_name);

    // Clean up
    free(null_terminated_group_name);

    // Close the group if it was successfully opened
    if (group_id >= 0) {
        H5Gclose(group_id);
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

    LLVMFuzzerTestOneInput_117(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
