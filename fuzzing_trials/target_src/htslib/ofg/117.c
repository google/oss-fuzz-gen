#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "/src/htslib/htslib/sam.h" // Correct header file for bam_aux_append

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    bam1_t bam;
    bam.data = (uint8_t *)malloc(size);
    if (bam.data == NULL) {
        return 0; // Exit if memory allocation fails
    }
    bam.l_data = size;
    memcpy(bam.data, data, size);

    // Ensure the tag is a valid two-character string
    char tag[3] = "XX";
    if (size >= 2) {
        tag[0] = (char)data[0];
        tag[1] = (char)data[1];
    }

    // Set a valid type character
    char type = 'A'; // Assuming 'A' is a valid type character

    // Set a valid length
    int len = (int)size;

    // Call the function-under-test
    bam_aux_append(&bam, tag, type, len, data);

    // Clean up
    free(bam.data);

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

    LLVMFuzzerTestOneInput_117(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
