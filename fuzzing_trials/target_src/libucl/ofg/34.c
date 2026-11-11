#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure that the data is not empty
    if (size == 0) {
        return 0;
    }

    // Convert the input data to a null-terminated string
    char *input_string = (char *)malloc(size + 1);
    if (input_string == NULL) {
        return 0;
    }

    memcpy(input_string, data, size);
    input_string[size] = '\0';

    // Call the function-under-test
    ucl_object_t *obj = ucl_object_fromlstring(input_string, size);

    // Clean up
    if (obj != NULL) {
        ucl_object_unref(obj);
    }
    free(input_string);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
