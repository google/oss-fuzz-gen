#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // Include this for ssize_t

// Function-under-test declaration
ssize_t sam_parse_cigar(const char *cigar, char **end, uint32_t **cigar_op, size_t *n_cigar_op);

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the CIGAR string and ensure it's null-terminated
    char *cigar = (char *)malloc(size + 1);
    if (cigar == NULL) {
        return 0;
    }
    memcpy(cigar, data, size);
    cigar[size] = '\0';

    // Initialize the parameters for the function-under-test
    char *end = NULL;
    uint32_t *cigar_op = NULL;
    size_t n_cigar_op = 0;

    // Call the function-under-test
    ssize_t result = sam_parse_cigar(cigar, &end, &cigar_op, &n_cigar_op);

    // Clean up allocated memory
    free(cigar);
    free(cigar_op);

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

    LLVMFuzzerTestOneInput_1(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
