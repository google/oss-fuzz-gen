#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test
void ly_pattern_free(void *ptr);

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Allocate memory for the pattern, ensuring it's not NULL
    void *pattern = malloc(size + 1);
    if (pattern == NULL) {
        return 0;
    }

    // Copy the fuzzing data into the allocated memory
    memcpy(pattern, data, size);

    // Null-terminate the pattern to ensure it's a valid string
    ((char *)pattern)[size] = '\0';

    // Call the function-under-test
    ly_pattern_free(pattern);

    // Free the allocated memory
    free(pattern);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
