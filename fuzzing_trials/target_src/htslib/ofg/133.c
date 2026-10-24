#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    sam_hdr_t *hdr = NULL;
    char *type = NULL;
    int pos = 0;
    
    // Ensure there is enough data to initialize parameters
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Allocate memory for the type string and copy data into it
    type = (char *)malloc(size + 1);
    if (type == NULL) {
        return 0;
    }
    memcpy(type, data, size);
    type[size] = '\0'; // Null-terminate the string

    // Use the first few bytes of data for the integer position
    memcpy(&pos, data, sizeof(int));

    // Initialize a dummy sam_hdr_t object
    hdr = sam_hdr_init();
    if (hdr == NULL) {
        free(type);
        return 0;
    }

    // Call the function-under-test
    const char *result = sam_hdr_line_name(hdr, type, pos);

    // Clean up
    sam_hdr_destroy(hdr);
    free(type);

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

    LLVMFuzzerTestOneInput_133(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
