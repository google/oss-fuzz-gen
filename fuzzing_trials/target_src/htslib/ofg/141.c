#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the correct path for the header file
#include "/src/htslib/htslib/hfile.h"

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to avoid out-of-bounds access
    if (size < 3) return 0;

    // Allocate memory for the char* parameter
    char *scheme = (char *)malloc(size + 1);
    if (!scheme) return 0;

    // Copy data to scheme and null-terminate it
    memcpy(scheme, data, size);
    scheme[size] = '\0';

    // Prepare the other parameters
    const char *schemes[] = {"http", "https", "ftp", "file"};
    int count = 0;

    // Call the function-under-test
    hfile_list_schemes(scheme, schemes, &count);

    // Free allocated memory
    free(scheme);

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

    LLVMFuzzerTestOneInput_141(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
