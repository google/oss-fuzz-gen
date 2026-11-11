#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/sam.h" // Correct path for sam.h

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Initialize a sam_hdr_t object
    sam_hdr_t *hdr = sam_hdr_init();

    // Ensure hdr is not NULL
    if (hdr == NULL) {
        return 0;
    }

    // Create a string from the input data
    char *name = (char *)malloc(size + 1);
    if (name == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(name, data, size);
    name[size] = '\0'; // Null-terminate the string

    // Add a dummy sequence header to hdr to make sam_hdr_name2tid meaningful
    const char *dummy_seq = "@SQ\tSN:dummy\tLN:1000\n";
    if (sam_hdr_add_lines(hdr, dummy_seq, strlen(dummy_seq)) < 0) {
        free(name);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Call the function-under-test
    int result = sam_hdr_name2tid(hdr, name);

    // Clean up
    free(name);
    sam_hdr_destroy(hdr);

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

    LLVMFuzzerTestOneInput_47(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
