#include <stdint.h>
#include <stddef.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Call the function-under-test
    ucl_object_t *obj = ucl_object_new();

    // Ensure the object is not NULL
    if (obj != NULL) {
        // If data is not NULL and size is greater than 0, add a string to the object
        if (data != NULL && size > 0) {
            char *str = (char *)malloc(size + 1);
            if (str != NULL) {
                memcpy(str, data, size);
                str[size] = '\0';  // Null-terminate the string
                ucl_object_insert_key(obj, ucl_object_fromstring(str), "key", 0, false);
                free(str);
            }
        }
        // Free the object
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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
