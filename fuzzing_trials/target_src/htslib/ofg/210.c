#include <stdint.h>
#include <stddef.h>
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    // Initialize bam1_t structure
    bam1_t *b = bam_init1();
    if (!b) return 0;

    // Initialize parameters for bam_set1
    size_t l_data = size > 0 ? size : 1; // Ensure non-zero size
    const char *qname = "example_qname"; // Example query name
    uint16_t flag = 0; // Example flag
    int32_t tid = 0; // Example target ID
    hts_pos_t pos = 0; // Example position
    uint8_t mapq = 255; // Example mapping quality
    size_t n_cigar = 1; // Example number of CIGAR operations
    uint32_t cigar[1] = {0}; // Example CIGAR array
    int32_t mtid = -1; // Example mate target ID
    hts_pos_t mpos = 0; // Example mate position
    hts_pos_t isize = 0; // Example insert size
    size_t l_seq = size > 0 ? size : 1; // Ensure non-zero sequence length
    const char *seq = "A"; // Example sequence
    const char *qual = "*"; // Example quality string
    size_t l_aux = size > 0 ? size : 1; // Ensure non-zero auxiliary data length

    // Call the function-under-test
    int result = bam_set1(b, l_data, qname, flag, tid, pos, mapq, n_cigar, cigar, mtid, mpos, isize, l_seq, seq, qual, l_aux);

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

    LLVMFuzzerTestOneInput_210(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
