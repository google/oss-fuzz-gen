#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h" // Correct path for the header file
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to safely use as a C-string
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0; // Exit if memory allocation fails
    }

    memcpy(inputString, data, size);
    inputString[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    char **result = lou_findTables(inputString);

    // Free the result if necessary
    if (result != NULL) {
        for (char **ptr = result; *ptr != NULL; ++ptr) {
            free(*ptr);
        }
        free(result);
    }

    // Free the allocated input string
    free(inputString);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
