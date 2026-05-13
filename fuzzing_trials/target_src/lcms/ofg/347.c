#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_347(const uint8_t *data, size_t size) {
    cmsSEQ *sequence;

    // Allocate memory for cmsSEQ
    sequence = (cmsSEQ *)malloc(sizeof(cmsSEQ));
    if (sequence == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the sequence with some non-NULL values
    sequence->n = 1; // Set the number of elements
    sequence->seq = (cmsPSEQDESC *)malloc(sizeof(cmsPSEQDESC) * sequence->n);
    if (sequence->seq == NULL) {
        free(sequence);
        return 0; // Exit if memory allocation fails
    }

    // Fill in some dummy data for the sequence
    for (unsigned int i = 0; i < sequence->n; i++) {
        sequence->seq[i].ProfileID.ID8[0] = (cmsUInt8Number)(data[i % size]);
        sequence->seq[i].Description = cmsMLUalloc(NULL, 1);
        if (sequence->seq[i].Description != NULL) {
            cmsMLUsetASCII(sequence->seq[i].Description, "en", "US", "Test Description");
        }
    }

    // Call the function-under-test
    cmsFreeProfileSequenceDescription(sequence);

    // Free allocated memory
    for (unsigned int i = 0; i < sequence->n; i++) {
        if (sequence->seq[i].Description != NULL) {
            cmsMLUfree(sequence->seq[i].Description);
        }
    }
    free(sequence->seq);
    free(sequence);

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

    LLVMFuzzerTestOneInput_347(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
