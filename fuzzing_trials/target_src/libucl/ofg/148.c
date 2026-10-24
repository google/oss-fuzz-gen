#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Call the function-under-test
    ucl_object_t *obj = ucl_object_new();

    // Use 'data' and 'size' to manipulate the object or test further functions
    if (size > 0) {
        ucl_object_t *str_obj = ucl_object_fromstring_common((const char *)data, size, 0);
        if (str_obj != NULL) {
            ucl_object_unref(str_obj);
        }
    }

    // Free the allocated object to avoid memory leaks
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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
