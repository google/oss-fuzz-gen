#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *new_obj = ucl_object_typed_new(UCL_OBJECT);
    const char *key = "test_key"; // Example key
    size_t keylen = 8; // Length of "test_key"
    bool copy_key = true;

    // Ensure that the input size is sufficient for testing
    if (size > 0) {
        // Call the function-under-test
        bool result = ucl_object_replace_key(obj, new_obj, key, keylen, copy_key);

        // Use the result in some way (here we just suppress unused variable warning)
        (void)result;
    }

    // Clean up
    ucl_object_unref(obj);
    ucl_object_unref(new_obj);

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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
