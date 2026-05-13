#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <htslib/sam.h>  // Include the necessary header for bam_mplp_t

// Dummy function to use as bam_plp_auto_f
int dummy_func(void *data, bam1_t *b) {
    return -1;  // Return -1 to indicate no more reads
}

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Prepare dummy data for bam_mplp_init
    int n = 1;  // Number of iterators
    void *dummy_data = NULL;  // Dummy data array

    // Create a bam_mplp_t object using the appropriate functions from htslib
    bam_mplp_t mplp = bam_mplp_init(n, dummy_func, &dummy_data);
    if (mplp == NULL) {
        return 0; // Exit if creation failed
    }

    // Call the function-under-test
    bam_mplp_reset(mplp);

    // Clean up
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_108(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
