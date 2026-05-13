#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/sam.h" // Assuming bam1_t is defined in this header

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    bam1_t *bam_record = bam_init1(); // Initialize a BAM record

    // Ensure the input size is sufficient for a BAM record
    if (size < sizeof(bam1_t)) {
        bam_destroy1(bam_record);
        return 0;
    }

    // Allocate memory for bam_record's data field
    bam_record->l_data = size;
    bam_record->m_data = size;
    bam_record->data = (uint8_t *)malloc(size);
    if (bam_record->data == NULL) {
        bam_destroy1(bam_record);
        return 0;
    }
    memcpy(bam_record->data, data, size);

    // Ensure that the bam_record is properly initialized before calling bam_aux_next
    // Set core fields to some valid values to ensure bam_aux_next is invoked
    bam_record->core.l_qname = 1; // Set to a non-zero value
    bam_record->core.n_cigar = 1; // Set to a non-zero value
    bam_record->core.l_qseq = 1;  // Set to a non-zero value

    // Ensure the data field is properly terminated or formatted if required
    // This is a speculative fix; ensure the data is valid for bam_aux_next
    if (bam_record->l_data > 0) {
        bam_record->data[bam_record->l_data - 1] = '\0'; // Null-terminate if necessary
    }

    // Call the function-under-test
    uint8_t *aux_data = bam_aux_next(bam_record, bam_record->data);

    // Check if aux_data is valid
    if (aux_data != NULL) {
        // Process aux_data if needed
    }

    // Clean up
    bam_destroy1(bam_record);

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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
