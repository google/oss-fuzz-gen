#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

// Assuming UCL_TYPE_MAX_ENUM is the correct constant for the maximum value of ucl_type_t
#ifndef UCL_TYPE_MAX_ENUM
#define UCL_TYPE_MAX_ENUM 7 // Hypothetical value, replace with actual maximum if known
#endif

int LLVMFuzzerTestOneInput_191(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract a ucl_type_t value
    if (size < sizeof(ucl_type_t)) {
        return 0;
    }

    // Extract a ucl_type_t value from the input data
    ucl_type_t type = (ucl_type_t)(data[0] % UCL_TYPE_MAX_ENUM); // Ensure type is within valid range

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_typed_new(type);

    // Clean up the created object
    if (obj != NULL) {
        ucl_object_unref(obj);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_191(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
