#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>
#include <stdbool.h> // Include this header for the bool type

int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Initialize a ucl_object_t instance
    ucl_object_t *obj = ucl_object_new();

    // Ensure the obj is not NULL
    if (obj == NULL) {
        return 0;
    }

    // Use the size from the fuzzer input as the reserve size
    size_t reserve_size = size > 0 ? size : 1; // Ensure reserve_size is not zero

    // Call the function-under-test
    bool result = ucl_object_reserve(obj, reserve_size);

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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
