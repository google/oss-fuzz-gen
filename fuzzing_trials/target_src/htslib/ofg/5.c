#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/hts_defs.h>
#include <htslib/sam.h> // Include the relevant header for hts_base_mod_state and related functions

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Call the function-under-test
    hts_base_mod_state *state = hts_base_mod_state_alloc();

    // If the function returns a non-NULL pointer, free the allocated memory
    if (state != NULL) {
        // Perform any necessary cleanup or further operations on `state`
        hts_base_mod_state_free(state); // Free the allocated state
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

    LLVMFuzzerTestOneInput_5(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
