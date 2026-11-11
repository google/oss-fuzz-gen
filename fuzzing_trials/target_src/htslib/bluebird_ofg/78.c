#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/sam.h"  // Ensure to include the HTSlib header for bam1_t

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0; // Ensure there's enough data for the parameters
    }

    // Initialize bam1_t structure
    bam1_t *bam = bam_init1();
    if (bam == NULL) {
        return 0; // Memory allocation failed
    }

    // Prepare the parameters for bam_aux_append
    const char *tag = "XX"; // Example tag, must be 2 characters
    char type = 'Z'; // Example type, 'Z' for string
    int len = size - 4; // Length of the data for the auxiliary field
    const uint8_t *aux_data = data + 4; // Auxiliary data starts after the first 4 bytes

    // Call the function-under-test
    int result = bam_aux_append(bam, tag, type, len, aux_data);

    // Clean up
    bam_destroy1(bam);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
