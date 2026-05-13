#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include "htslib/sam.h" // Assuming bam_plp_t is defined in this header

// Define a callback function for bam_plp_init
int dummy_callback(const bam1_t *b, void *data) {
    // A simple callback that always returns 1
    return 1;
}

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create a bam1_t structure
    if (size < sizeof(bam1_t)) {
        return 0;
    }

    // Allocate memory for bam1_t
    bam1_t *b = bam_init1();
    if (b == NULL) {
        return 0;
    }

    // Initialize the bam1_t structure with the input data
    // Ensure that the data pointer is valid and the memory is allocated
    b->data = (uint8_t *)malloc(size);
    if (b->data == NULL) {
        bam_destroy1(b);
        return 0;
    }

    // Copy data into bam1_t structure
    memcpy(b->data, data, size);
    b->m_data = size; // Set the size of the allocated memory
    b->l_data = size; // Set the length of the data

    // Initialize bam_plp_t with a dummy callback
    bam_plp_t plp = bam_plp_init(dummy_callback, NULL);

    if (plp != NULL) {
        // Push the bam1_t data into the pileup
        bam_plp_push(plp, b);

        // Call the function-under-test
        bam_plp_reset(plp);

        // Clean up
        bam_plp_destroy(plp);
    }

    // Free the bam1_t structure
    // The bam1_t structure's data field was allocated and must be freed
    free(b->data);
    // Set the data pointer to NULL to avoid double-free
    b->data = NULL;
    bam_destroy1(b);

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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
