#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for a key
    if (size < 1) {
        return 0;
    }

    // Initialize a dummy ucl_object_t
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    if (obj == NULL) {
        return 0;
    }

    // Use the data as a key, ensuring it's null-terminated
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        ucl_object_unref(obj);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Call the function-under-test
    bool result = ucl_object_delete_keyl(obj, key, size);

    // Clean up
    free(key);
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_190(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
