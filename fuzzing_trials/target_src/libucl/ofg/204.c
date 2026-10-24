#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_204(const uint8_t *data, size_t size) {
    ucl_object_t *obj;
    size_t key_len;

    // Initialize the ucl_object_t with some data
    obj = ucl_object_new();
    if (obj == NULL) {
        return 0; // Handle error in object creation
    }
    obj->key = (const char *)data;
    obj->keylen = size;

    // Call the function-under-test
    const char *key = ucl_object_keyl(obj, &key_len);

    // Use the returned key and key_len in some way to avoid compiler optimizations
    if (key != NULL && key_len > 0) {
        // Do something with key and key_len, e.g., print or store
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_204(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
