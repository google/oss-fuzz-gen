#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Mock JanetCFunction type for demonstration purposes
typedef void (*JanetCFunction)(void);

// Example function to be used as a JanetCFunction
void exampleJanetCFunction(void) {
    // Function implementation
}

// Function-under-test
void janet_register(const char *name, JanetCFunction func);

// Fuzzing harness
int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *name = (char *)malloc(size + 1);
    if (!name) {
        return 0;
    }

    // Copy the data into the name buffer and null-terminate it
    memcpy(name, data, size);
    name[size] = '\0';

    // Call the function-under-test
    janet_register(name, exampleJanetCFunction);

    // Free the allocated memory
    free(name);

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

    LLVMFuzzerTestOneInput_96(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
