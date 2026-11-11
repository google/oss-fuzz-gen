#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> // Include for memcpy
#include "htslib/sam.h" // Include the necessary header for bam_mplp_t and related functions

// Function prototype for a dummy bam_plp_auto_f function
int dummy_bam_plp_auto(bam_plp_t iter, void *data) {
    // This is a placeholder function to satisfy the bam_mplp_init requirements
    return 0;
}

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to proceed
    if (size < sizeof(bam1_t)) {
        return 0;
    }

    // Declare and initialize bam_mplp_t variable
    bam_mplp_t mplp;

    // Create a dummy data array to pass to bam_mplp_init
    void *dummy_data[1] = {NULL};

    // Initialize the bam_mplp_t variable with the correct number of arguments
    mplp = bam_mplp_init(1, dummy_bam_plp_auto, dummy_data);

    // Simulate a bam1_t structure to pass to the function
    bam1_t *b = bam_init1();
    if (!b) {
        bam_mplp_destroy(mplp);
        return 0;
    }

    // Ensure there's enough data to fill the bam1_t structure
    // Copy only the data part of bam1_t, not the whole structure
    // Ensure that the bam1_t structure's data field is properly allocated
    if (b->m_data < size) {
        b->m_data = size;
        b->data = (uint8_t *)realloc(b->data, b->m_data);
        if (!b->data) {
            bam_destroy1(b);
            bam_mplp_destroy(mplp);
            return 0;
        }
    }
    memcpy(b->data, data, size);

    // Call the function-under-test
    int result = bam_mplp_init_overlaps(mplp);

    // Clean up
    bam_destroy1(b);
    bam_mplp_destroy(mplp);

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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
