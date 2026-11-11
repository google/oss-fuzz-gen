#include <stdint.h>
#include <stddef.h>
#include <cstring> // Include for memcpy

// Assuming the lou_charSize function is defined in a C library
extern "C" {
    // Modify the function signature to accept input data
    int lou_charSize(const uint8_t *data);
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Check if the input size is valid for the function
    if (size == 0) {
        return 0;
    }

    // Create a buffer to ensure the data passed to lou_charSize is null-terminated
    uint8_t *buffer = new uint8_t[size + 1];
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test with the input data
    int result = lou_charSize(buffer);
    
    // Use the result in some way to avoid compiler optimizations removing the call
    if (result < 0) {
        delete[] buffer; // Clean up allocated memory
        return 1;
    }

    delete[] buffer; // Clean up allocated memory
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
