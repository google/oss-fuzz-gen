#include <stdint.h>
#include <stddef.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for at least one uint32_t element
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Calculate the number of uint32_t elements we can extract from the data
    int n_cigar = size / sizeof(uint32_t);

    // Cast the data to a uint32_t pointer
    const uint32_t *cigar = (const uint32_t *)data;

    // Call the function-under-test
    hts_pos_t result = bam_cigar2rlen(n_cigar, cigar);

    // Use the result in some way to prevent optimization out (not strictly necessary)
    (void)result;

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

    LLVMFuzzerTestOneInput_175(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
