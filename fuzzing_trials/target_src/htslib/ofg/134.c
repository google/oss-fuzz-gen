#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Assuming sam_hdr_t is defined somewhere in the included headers
typedef struct {
    // Dummy structure for the sake of example
    int dummy;
} sam_hdr_t;

// Dummy implementation of sam_hdr_line_name_134 for the sake of example
const char * sam_hdr_line_name_134(sam_hdr_t *hdr, const char *type, int index) {
    // Dummy return value
    return "dummy_name";
}

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Initialize sam_hdr_t structure
    sam_hdr_t hdr;
    hdr.dummy = 0;  // Initialize with some value

    // Ensure there is enough data to create a non-null string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the data
    char *type = (char *)malloc(size + 1);
    if (type == NULL) {
        return 0;
    }
    memcpy(type, data, size);
    type[size] = '\0';

    // Use a fixed index for simplicity
    int index = 0;

    // Call the function-under-test
    const char *result = sam_hdr_line_name_134(&hdr, type, index);

    // Print the result for debugging purposes
    printf("Result: %s\n", result);

    // Free allocated memory
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

    LLVMFuzzerTestOneInput_134(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
