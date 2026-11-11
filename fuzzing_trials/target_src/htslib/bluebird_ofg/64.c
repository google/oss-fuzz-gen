#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "htslib/sam.h" // Correct path for bam1_t and bam_set_qname

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for bam1_t structure
    bam1_t *bam = (bam1_t *)malloc(sizeof(bam1_t));
    if (bam == NULL) {
        return 0;
    }

    // Initialize bam1_t structure with default values
    memset(bam, 0, sizeof(bam1_t));

    // Allocate memory for the qname string
    char *qname = (char *)malloc(size + 1);
    if (qname == NULL) {
        free(bam);
        return 0;
    }

    // Copy data to qname and ensure it is null-terminated
    memcpy(qname, data, size);
    qname[size] = '\0';

    // Call the function-under-test
    int result = bam_set_qname(bam, qname);

    // Clean up
    free(qname);
    free(bam);

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

    LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
