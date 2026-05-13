#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for malloc and free
#include <string.h>  // Include for memcpy
#include <ucl.h>

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Ensure that size is large enough to have meaningful input
    if (size < 2) {
        return 0;
    }

    // Create a ucl_object_t from the data
    ucl_object_t *ucl_obj = ucl_object_fromstring((const char *)data);

    // Use a portion of the data as the key for lookup
    size_t key_len = size / 2;
    char *key = (char *)malloc(key_len + 1);
    if (key == NULL) {
        ucl_object_unref(ucl_obj);
        return 0;
    }
    memcpy(key, data, key_len);
    key[key_len] = '\0'; // Null-terminate the key

    // Call the function-under-test
    const ucl_object_t *result = ucl_object_lookup_any(ucl_obj, key, NULL);

    // Clean up
    free(key);
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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
