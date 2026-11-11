#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to create meaningful inputs
    if (size < 3) {
        return 0;
    }

    // Initialize ucl_object_t pointers
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();

    // Create a string for comments
    char *comment = (char *)malloc(size + 1);
    if (comment == NULL) {
        ucl_object_unref(obj1);
        ucl_object_unref(obj2);
        return 0;
    }

    // Copy data into the comment string and null-terminate it
    memcpy(comment, data, size);
    comment[size] = '\0';

    // Call the function-under-test
    ucl_comments_add(obj1, obj2, comment);

    // Clean up
    free(comment);
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);

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

    LLVMFuzzerTestOneInput_177(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
