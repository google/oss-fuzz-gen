#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *ucl_obj = ucl_object_new();
    const char *key;
    size_t key_len;

    // Ensure size is sufficient for a key
    if (size < 1) {
        ucl_object_unref(ucl_obj);
        return 0;
    }

    // Use the first byte of data as the key length
    key_len = data[0];

    // Ensure key_len is within bounds of the data size
    if (key_len > size - 1) {
        key_len = size - 1;
    }

    // Set key to the data after the first byte
    key = (const char *)(data + 1);

    // Call the function-under-test
    ucl_object_t *result = ucl_object_pop_keyl(ucl_obj, key, key_len);

    // Clean up
    if (result != NULL) {
        ucl_object_unref(result);
    }
    ucl_object_unref(ucl_obj);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
