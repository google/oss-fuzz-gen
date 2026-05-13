#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <htslib/sam.h>  // Ensure you have the htslib library installed

// Remove the extern "C" linkage specification for C++
// since this is a C program
int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for testing
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the CIGAR string
    char *cigar_str = (char *)malloc(size + 1);
    if (cigar_str == NULL) {
        return 0;
    }

    // Copy data into the CIGAR string and null-terminate it
    memcpy(cigar_str, data, size);
    cigar_str[size] = '\0';

    // Allocate memory for the parsed CIGAR operations
    char *cigar_parsed = NULL;

    // Initialize a bam1_t structure
    bam1_t *bam_record = bam_init1();
    if (bam_record == NULL) {
        free(cigar_str);
        return 0;
    }

    // Call the function-under-test
    ssize_t result = bam_parse_cigar(cigar_str, &cigar_parsed, bam_record);

    // Clean up allocated resources
    free(cigar_str);
    free(cigar_parsed);
    bam_destroy1(bam_record);

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

    LLVMFuzzerTestOneInput_37(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
