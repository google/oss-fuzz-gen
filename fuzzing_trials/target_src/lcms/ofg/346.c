#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy
#include <lcms2.h>   // Include the Little CMS library header

int LLVMFuzzerTestOneInput_346(const uint8_t *data, size_t size) {
    cmsSEQ *sequence = NULL;

    // Check if the size is sufficient to create a cmsSEQ object
    if (size >= sizeof(cmsSEQ)) {
        // Allocate memory for the cmsSEQ object
        sequence = (cmsSEQ *)malloc(sizeof(cmsSEQ));
        if (sequence != NULL) {
            // Initialize the cmsSEQ object with the input data
            memcpy(sequence, data, sizeof(cmsSEQ));

            // Call the function-under-test
            cmsFreeProfileSequenceDescription(sequence);
        }
    }

    // Free the allocated memory
    if (sequence != NULL) {
        free(sequence);
    }

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

    LLVMFuzzerTestOneInput_346(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
