#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Initialize ucl_object_t pointers
    ucl_object_t *obj1 = ucl_object_new();
    const ucl_object_t *obj2 = ucl_object_new();
    const ucl_object_t *obj3 = ucl_object_new();

    // Check if the objects were created successfully
    if (obj1 == NULL || obj2 == NULL || obj3 == NULL) {
        // Clean up if any object creation failed
        if (obj1 != NULL) ucl_object_unref(obj1);
        if (obj2 != NULL) ucl_object_unref((ucl_object_t *)obj2);
        if (obj3 != NULL) ucl_object_unref((ucl_object_t *)obj3);
        return 0;
    }

    // Call the function-under-test
    ucl_comments_move(obj1, obj2, obj3);

    // Clean up
    ucl_object_unref(obj1);
    ucl_object_unref((ucl_object_t *)obj2);
    ucl_object_unref((ucl_object_t *)obj3);

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

    LLVMFuzzerTestOneInput_194(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
