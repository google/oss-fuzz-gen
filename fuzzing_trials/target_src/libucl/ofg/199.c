#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the input string and ensure it's null-terminated
    char *input_string = (char *)malloc(size + 1);
    if (input_string == NULL) {
        return 0;
    }
    memcpy(input_string, data, size);
    input_string[size] = '\0';

    // Initialize ucl_type_t variable
    ucl_type_t type;

    // Call the function-under-test
    bool result = ucl_object_string_to_type(input_string, &type);

    // Clean up
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

    LLVMFuzzerTestOneInput_199(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
