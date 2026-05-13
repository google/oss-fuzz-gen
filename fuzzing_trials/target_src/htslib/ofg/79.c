#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "htslib/sam.h"

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    bam1_t *b = bam_init1();
    const char *tag = "XX";  // Example tag, should be 2 characters long
    int64_t value = 0;

    // Ensure the size is sufficient to extract an int64_t value
    if (size >= sizeof(int64_t)) {
        // Copy the first 8 bytes of data into value
        memcpy(&value, data, sizeof(int64_t));
    }

    // Call the function-under-test
    int result = bam_aux_update_int(b, tag, value);

    // Clean up
    bam_destroy1(b);

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

    LLVMFuzzerTestOneInput_79(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
