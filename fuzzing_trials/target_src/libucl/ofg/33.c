#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Ensure the input data is null-terminated for string processing
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Define a valid enumeration value for ucl_string_flags
    enum ucl_string_flags flags = UCL_STRING_RAW;

    // Call the function-under-test
    ucl_object_t *result = ucl_object_fromstring_common(input_str, size, flags);

    // Clean up
    if (result != NULL) {
        ucl_object_unref(result);
    }
    free(input_str);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
