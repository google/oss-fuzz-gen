#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/hts.h" // Include the header for hts_free

// Dummy implementation of process_data function
void process_data(void *data, size_t size) {
    // Example processing: just print the data size
    printf("Processing data of size: %zu\n", size);
}

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to provide meaningful input
    if (size == 0) {
        return 0;
    }

    // Allocate memory for fuzzing
    void *memory = malloc(size + 1); // Ensure memory is not NULL
    if (memory == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data to the allocated memory
    memcpy(memory, data, size);

    // Ensure the memory is null-terminated if used as a string
    ((char *)memory)[size] = '\0';

    // Call the function-under-test with meaningful input
    process_data(memory, size);

    // Free the allocated memory
    hts_free(memory);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_110(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
