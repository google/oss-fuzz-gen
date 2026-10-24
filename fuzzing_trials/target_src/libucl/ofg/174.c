#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>
#include <string.h>

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Initialize a ucl_object_t
    ucl_object_t *ucl_obj = ucl_object_new();

    // Ensure the first byte is used as a key length
    size_t key_len = data[0] % (size - 1);
    if (key_len == 0) {
        key_len = 1;
    }

    // Ensure the key is null-terminated
    char key[key_len + 1];
    memcpy(key, data + 1, key_len);
    key[key_len] = '\0';

    // Call the function-under-test
    bool result = ucl_object_delete_key(ucl_obj, key);

    // Clean up
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

    LLVMFuzzerTestOneInput_174(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
