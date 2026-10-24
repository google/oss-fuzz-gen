#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "ucl.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to be used
    if (size == 0) {
        return 0;
    }

    // Allocate memory for ucl_object_t
    ucl_object_t *obj = ucl_object_new();

    // Initialize the ucl_object_t with data
    // Assuming data is a valid representation for the ucl_object_t
    // This is just a placeholder as the actual initialization will depend on the library specifics
    obj->key = (char *)data;
    obj->keylen = size;

    // Call the function-under-test
    double result = ucl_object_todouble(obj);

    // Clean up
    ucl_object_unref(obj);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
