#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a ucl_object_t
    if (size < sizeof(ucl_object_t)) {
        return 0;
    }

    // Allocate memory for a ucl_object_t
    ucl_object_t *obj = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    if (obj == NULL) {
        return 0;
    }

    // Initialize the ucl_object_t with data
    obj->type = UCL_OBJECT; // Set a valid type
    obj->key = (const char *)data; // Assign data as key
    obj->keylen = size; // Set key length

    // Call the function-under-test
    ucl_object_t *ref_obj = ucl_object_ref(obj);

    // Clean up
    if (ref_obj) {
        ucl_object_unref(ref_obj);
    }
    free(obj);

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

    LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
