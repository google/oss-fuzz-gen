#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Initialize UCL object
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);

    // Use the data to create a key string
    char key[size + 1];
    memcpy(key, data, size);
    key[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    bool result = ucl_object_delete_key(obj, key);

    // Clean up UCL object
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
