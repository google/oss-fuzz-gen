#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/htslib/htslib/sam.h" // Correct path for sam_hdr_parse

// Include the necessary header for sam_hdr_free
#include "/src/htslib/htslib/hts.h" // This header typically contains sam_hdr_free

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Ensure the data is null-terminated for the string input
    char *data_str = (char *)malloc(size + 1);
    if (data_str == NULL) {
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    // Call the function-under-test
    sam_hdr_t *hdr = sam_hdr_parse(size, data_str);

    // Clean up
    free(data_str);
    if (hdr != NULL) {
        // Use the correct function to free the sam_hdr_t
        sam_hdr_destroy(hdr); // Corrected function name
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

    LLVMFuzzerTestOneInput_121(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
