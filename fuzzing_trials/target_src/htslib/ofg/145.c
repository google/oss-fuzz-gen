#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h>  // Ensure you have the HTSlib library installed and included

// Remove the 'extern "C"' as this is a C code, not C++
int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t)) {
        // Not enough data to form even a single uint32_t element
        return 0;
    }

    // Calculate the number of uint32_t elements we can extract from data
    int num_elements = size / sizeof(uint32_t);

    // Allocate memory for the uint32_t array
    uint32_t *cigar_array = (uint32_t *) malloc(num_elements * sizeof(uint32_t));
    if (cigar_array == NULL) {
        return 0;  // Allocation failed
    }

    // Copy data into the uint32_t array
    for (int i = 0; i < num_elements; i++) {
        cigar_array[i] = ((uint32_t *)data)[i];
    }

    // Call the function-under-test
    hts_pos_t result = bam_cigar2qlen(num_elements, cigar_array);

    // Free allocated memory
    free(cigar_array);

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

    LLVMFuzzerTestOneInput_145(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
