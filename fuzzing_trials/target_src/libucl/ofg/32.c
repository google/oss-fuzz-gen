#include <stddef.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the size is at least 1 to extract a flag
    if (size < 1) {
        return 0;
    }

    // Extract the flag from the data
    enum ucl_string_flags flags = (enum ucl_string_flags)data[0];

    // Ensure the string is not empty
    const char *inputString = (const char *)(data + 1);
    size_t stringSize = size - 1;

    // Call the function under test
    ucl_object_t *result = ucl_object_fromstring_common(inputString, stringSize, flags);

    // Clean up the result if needed
    if (result != NULL) {
        ucl_object_unref(result);
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
