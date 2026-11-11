#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>  // Include this for memcpy
#include "htslib/sam.h"  // Assuming bam_parse_cigar is declared in this header

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Ensure the input data is null-terminated for string operations
    char *cigar_str = (char *)malloc(size + 1);
    if (cigar_str == NULL) return 0;
    memcpy(cigar_str, data, size);
    cigar_str[size] = '\0';

    // Prepare the other parameters for bam_parse_cigar
    char *end = NULL;
    bam1_t *bam_record = bam_init1(); // Initialize bam1_t structure

    if (bam_record == NULL) {
        free(cigar_str);
        return 0;
    }

    // Call the function-under-test
    ssize_t result = bam_parse_cigar(cigar_str, &end, bam_record);

    // Clean up
    bam_destroy1(bam_record);
    free(cigar_str);

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

    LLVMFuzzerTestOneInput_38(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
