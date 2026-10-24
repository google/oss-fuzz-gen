#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // Include the standard library for malloc and free

// Function under test
int bam_str2flag(const char *str);

// Fuzzing harness
int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and non-empty
    if (size == 0) {
        return 0;
    }

    // Create a buffer with an extra byte for the null terminator
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        // Handle malloc failure
        return 0;
    }
    
    // Copy the data into the buffer and null-terminate it
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Call the function under test
    bam_str2flag(input_str);

    // Clean up
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_75(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
