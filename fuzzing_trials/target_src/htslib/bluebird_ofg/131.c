#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/sam.h"  // Correct path for bam1_t and bam_copy1

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for the bam1_t structure and its data
    if (size < sizeof(bam1_t)) {
        return 0; // Not enough data to form a bam1_t structure
    }

    // Allocate memory for two bam1_t structures
    bam1_t *dest = bam_init1();
    bam1_t *src = bam_init1();

    if (dest == NULL || src == NULL) {
        bam_destroy1(dest);
        bam_destroy1(src);
        return 0;
    }

    // Initialize the source bam1_t structure with input data
    memcpy(src, data, sizeof(bam1_t));

    // Ensure the rest of the bam1_t structure is initialized
    if (src->m_data > 0) {
        src->data = (uint8_t *)malloc(src->m_data);
        if (src->data != NULL && size > sizeof(bam1_t)) {
            size_t copy_size = size - sizeof(bam1_t);
            if (copy_size > src->m_data) {
                copy_size = src->m_data;
            }
            memcpy(src->data, data + sizeof(bam1_t), copy_size);
        } else if (src->data == NULL) {
            bam_destroy1(dest);
            bam_destroy1(src);
            return 0;
        }
    } else {
        src->data = NULL;
    }

    // Validate the src bam1_t structure before calling bam_copy1
    // Ensure l_data does not exceed m_data
    if (src->l_data > src->m_data) {
        bam_destroy1(dest);
        bam_destroy1(src);
        return 0;
    }

    // Call the function-under-test
    bam1_t *result = bam_copy1(dest, src);

    // Check for successful copy
    if (result == NULL) {
        bam_destroy1(dest);
        bam_destroy1(src);
        return 0;
    }

    // Clean up
    bam_destroy1(dest);
    bam_destroy1(src);

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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
