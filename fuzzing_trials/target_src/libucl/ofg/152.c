#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two ucl_object_t pointers
    if (size < 2 * sizeof(ucl_object_t)) {
        return 0;
    }

    // Allocate memory for two ucl_object_t objects
    ucl_object_t *obj1 = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    ucl_object_t *obj2 = (ucl_object_t *)malloc(sizeof(ucl_object_t));

    if (!obj1 || !obj2) {
        free(obj1);
        free(obj2);
        return 0;
    }

    // Initialize the objects with some data from the input
    // Here we just use a portion of the data to initialize some fields
    obj1->key = (char *)data;
    obj1->len = size / 2;
    obj1->type = UCL_STRING;

    obj2->key = (char *)(data + size / 2);
    obj2->len = size / 2;
    obj2->type = UCL_STRING;

    // Create pointers to the objects
    const ucl_object_t *obj1_ptr = obj1;
    const ucl_object_t *obj2_ptr = obj2;

    // Call the function-under-test
    int result = ucl_object_compare_qsort(&obj1_ptr, &obj2_ptr);

    // Clean up
    free(obj1);
    free(obj2);

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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
