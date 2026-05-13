#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    bam_plp_t pileup = NULL;
    int tid = 0;
    hts_pos_t pos = 0;
    int n_plp = 0;

    // Initialize a dummy bam_plp_t object
    pileup = bam_plp_init(NULL, NULL);

    // Ensure the data size is sufficient for processing
    if (size > 0) {
        // Call the function-under-test
        const bam_pileup1_t *result = bam_plp64_auto(pileup, &tid, &pos, &n_plp);

        // Process the result if needed (for fuzzing purposes, we just call the function)
        if (result != NULL) {
            // Example processing: iterate over the pileup entries
            for (int i = 0; i < n_plp; ++i) {
                // Access each bam_pileup1_t entry
                const bam_pileup1_t *entry = &result[i];
                // Perform some dummy operations
                (void)entry->b;
                (void)entry->qpos;
            }
        }
    }

    // Clean up
    bam_plp_destroy(pileup);

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

    LLVMFuzzerTestOneInput_44(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
