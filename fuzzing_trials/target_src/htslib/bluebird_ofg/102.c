#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "htslib/sam.h" // Include the necessary header for bam_plp_auto

// Remove the 'extern "C"' as it is not compatible with C code
int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Declare and initialize the necessary variables
    bam_plp_t plp;
    int ref_id = 0;
    int pos = 0;
    int n_plp = 0;

    // Check if size is sufficient to create a bam_plp_t object
    if (size < sizeof(bam_plp_t)) {
        return 0;
    }

    // Initialize the bam_plp_t object
    plp = bam_plp_init(NULL, NULL);

    // Call the function-under-test
    const bam_pileup1_t *result = bam_plp_auto(plp, &ref_id, &pos, &n_plp);

    // Clean up
    bam_plp_destroy(plp);

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
