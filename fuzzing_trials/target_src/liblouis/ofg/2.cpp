#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
    // Include the necessary header for the function-under-test
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Define the function-under-test
extern "C" int lou_compileString(const char *table, const char *input);

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for creating two non-null strings
    if (size < 2) {
        return 0;
    }

    // Divide the input data into two halves for the two string parameters
    size_t mid = size / 2;

    // Allocate memory for the two strings and ensure they are null-terminated
    char *table = new char[mid + 1];
    char *input = new char[size - mid + 1];

    // Copy the data into the allocated strings
    std::memcpy(table, data, mid);
    std::memcpy(input, data + mid, size - mid);

    // Null-terminate the strings
    table[mid] = '\0';
    input[size - mid] = '\0';

    // Call the function-under-test
    lou_compileString(table, input);

    // Clean up the allocated memory
    delete[] table;
    delete[] input;

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
