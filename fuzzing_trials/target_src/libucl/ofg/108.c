#include <stdint.h>
#include <stdlib.h>
#include <ucl.h> // Correctly include the UCL library header

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    ucl_object_t *obj = NULL;
    ucl_object_t *ref_obj = NULL;

    // Ensure size is non-zero to avoid parsing issues
    if (size == 0) {
        return 0;
    }

    // Parse the input data into a UCL object
    obj = ucl_parser_add_chunk(NULL, data, size);
    if (obj == NULL) {
        return 0;
    }

    // Call the function-under-test
    ref_obj = ucl_object_ref(obj);

    // Clean up
    if (obj != NULL) {
        ucl_object_unref(obj);
    }
    if (ref_obj != NULL) {
        ucl_object_unref(ref_obj);
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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
