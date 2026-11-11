#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/hts.h"
#include "htslib/sam.h"  // Include the library that defines hts_base_mod_state

extern int bam_mods_queryi(hts_base_mod_state *state, int pos, int *strand, int *mod, char *canonical_base);

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hts_base_mod_state *state = hts_base_mod_state_alloc();
    int pos = 0;
    int strand = 0;
    int mod = 0;
    char canonical_base = 'A';  // Initialize with a valid base character

    // Ensure data is not empty
    if (size > 0) {
        // Use the first byte of data as position
        pos = data[0];

        // Use additional bytes if available to set other parameters
        if (size > 1) {
            strand = data[1] % 2;  // Assuming strand is a binary value
        }
        if (size > 2) {
            mod = data[2];  // Use third byte to set mod
        }
        if (size > 3) {
            canonical_base = "ACGT"[data[3] % 4];  // Map to one of the canonical bases
        }
    }

    // Call the function-under-test
    bam_mods_queryi(state, pos, &strand, &mod, &canonical_base);

    // Free allocated resources
    hts_base_mod_state_free(state);

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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
