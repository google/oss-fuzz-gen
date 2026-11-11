#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/sam.h> // Include additional htslib headers if necessary

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    // Ensure size is greater than 0 to avoid empty string issues
    if (size == 0) {
        return 0;
    }

    // Prepare a null-terminated string from the input data
    char *filter_expression = (char *)malloc(size + 1);
    if (!filter_expression) {
        return 0; // Memory allocation failed
    }
    memcpy(filter_expression, data, size);
    filter_expression[size] = '\0'; // Null-terminate the string

    // Create a dummy htsFile structure
    // Use a more realistic file format and mode if needed
    htsFile *hts_file = hts_open("dummy.bam", "r"); // Open a dummy file handle
    if (!hts_file) {
        free(filter_expression);
        return 0; // Failed to open dummy file
    }

    // Call the function-under-test
    // Ensure the function is properly invoked and can process the input
    int result = hts_set_filter_expression(hts_file, filter_expression);

    // Check the result for debugging purposes
    if (result != 0) {
        fprintf(stderr, "Failed to set filter expression: %s\n", filter_expression);
    }

    // Clean up
    hts_close(hts_file);
    free(filter_expression);

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

    LLVMFuzzerTestOneInput_151(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
